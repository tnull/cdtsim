use std::ops::{Add, AddAssign, Mul};
use statrs::distribution::{Normal, Continuous};
use statrs::statistics::{Mean, Variance};
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::collections::HashSet;
use std::rc::Rc;

#[allow(unused_imports)] 
use log::{info,debug,trace};

use crate::graph::{Graph, NodeId, NodeRef, EdgeRef};
use crate::pathfind::{EdgeWeight, edge_weight};

#[derive(Debug, Clone, Copy)]
pub struct CandidateDistribution (Normal);

impl CandidateDistribution {
    pub fn new(mean: f64, std_dev: f64) -> Self {
        Self (Normal::new(mean, std_dev).unwrap())
    }

    pub fn pdf(&self, x: f64) -> f64 {
        self.0.pdf(x)
    }

    pub fn mean(&self) -> f64 {
        self.0.mean()
    }

    pub fn std_dev(&self) -> f64 {
        self.0.std_dev()
    }
}

impl Add for CandidateDistribution {
    type Output = CandidateDistribution;
    fn add(self, other: CandidateDistribution) -> Self {
        let new_mean = self.0.mean() + other.0.mean();
        let new_variance = self.0.variance() + other.0.variance();
        let new_std_dev = new_variance.sqrt();
        Self (Normal::new(new_mean, new_std_dev).unwrap())
    }
}

impl AddAssign for CandidateDistribution {
    fn add_assign(&mut self, other: Self) {
        let new_mean = self.0.mean() + other.0.mean();
        let new_variance = self.0.variance() + other.0.variance();
        let new_std_dev = new_variance.sqrt();
        *self = Self (Normal::new(new_mean, new_std_dev).unwrap());
    }
}

impl Mul<f64> for CandidateDistribution {
    type Output = CandidateDistribution;
    fn mul(self, other: f64) -> Self {
        let new_mean = self.0.mean() * other;
        let new_variance = self.0.variance() * other;
        let new_std_dev = new_variance.sqrt();
        Self (Normal::new(new_mean, new_std_dev).unwrap())
    }
}

#[derive(Debug, Clone)]
pub struct CandidateHop {
    aggregated_distribution: CandidateDistribution,
    current_amount: u64,
    current_time_lock: u16,
    prev_hops: HashSet<NodeId>,
    prev_distributions: Vec<CandidateDistribution>,
}

impl CandidateHop {
    //pub fn new(mean: f64, std_dev: f64) -> Self {
    //    let aggregated_distribution = CandidateDistribution::new(mean, std_dev);
    //    let aggregated_amount = 0;
    //    let aggregated_time = 0;
    //    Self { aggregated_distribution, aggregated_amount, aggregated_time }
    //}
}

pub struct Adversary {
    graph: Box<Graph>,
    meas_node_ref: NodeRef,
    meas_edge_ref: EdgeRef,
    meas_amount: u64,
    meas_time_lock: u16,
    current_node_ref: NodeRef,
    candidate_map: BTreeMap<NodeId, CandidateHop>,
    visited: HashSet<NodeId>,
    to_visit: VecDeque<NodeId>,
}


impl Adversary {
    pub fn new(meas_node_ref: NodeRef, meas_edge_ref: EdgeRef, meas_amount: u64, meas_time_lock: u16, graph: Box<Graph>) -> Self {
        let meas_node_id = meas_node_ref.borrow().node_id();
        let current_node_ref = Rc::clone(&meas_node_ref);

        let mut candidate_map: BTreeMap<NodeId, CandidateHop> = BTreeMap::new();

        let mut visited = HashSet::new();
        let mut to_visit = VecDeque::new();


        visited.insert(meas_node_id);


        // as we know the next edge, start estimation at the first  neighbor
        let neighbor_id = meas_edge_ref.borrow().neighbor_id(meas_node_id).unwrap();
        to_visit.push_back(neighbor_id);

        let neighbor_hop_dist = estimate_latency_distribution(Rc::clone(&meas_edge_ref));
        let aggregated_distribution = neighbor_hop_dist * 4.0;

        let neighbor_amount = meas_amount;
        assert!(neighbor_amount <= meas_edge_ref.borrow().capacity());

        let neighbor_time_lock = meas_time_lock;

        let mut prev_hops =  HashSet::new();
        prev_hops.insert(meas_node_id);

        let mut prev_distributions = Vec::new();
        prev_distributions.push(neighbor_hop_dist);

        let neighbor_candidate = CandidateHop {
            aggregated_distribution: aggregated_distribution,
            current_amount: neighbor_amount,
            current_time_lock: neighbor_time_lock,
            prev_hops: prev_hops,
            prev_distributions: prev_distributions,
        };

        candidate_map.insert(neighbor_id, neighbor_candidate);
        Self { meas_node_ref, meas_edge_ref, meas_amount, meas_time_lock, current_node_ref, candidate_map, visited, graph, to_visit }
    }

    pub fn first_spy_estimate_source(&self) -> NodeRef {
        let meas_node_id = self.meas_node_ref.borrow().node_id();
        let neighbor_id = self.meas_edge_ref.borrow().neighbor_id(meas_node_id).unwrap();
        self.graph.get_node_ref(neighbor_id).unwrap()
    }

    pub fn first_spy_estimate_destination(&self) -> NodeRef {
        let meas_node_id = self.meas_node_ref.borrow().node_id();
        let neighbor_id = self.meas_edge_ref.borrow().neighbor_id(meas_node_id).unwrap();
        self.graph.get_node_ref(neighbor_id).unwrap()
    }

    pub fn timing_estimate_source(&mut self, meas_time_diff_millis: f64) -> NodeRef {
        while let Some(current_node_id) = self.next_to_visit() {
            if self.visited.contains(&current_node_id) {
                // skip if we already visited that node
                continue;
            }
            let current_node_ref = self.graph.get_node_ref(current_node_id).unwrap();
            self.current_node_ref = Rc::clone(&current_node_ref);
            let current_candidate = self.candidate_map.get(&current_node_id).unwrap();
            let current_aggregated_dist = current_candidate.aggregated_distribution;
            let current_amount = current_candidate.current_amount;
            let current_time_lock = current_candidate.current_time_lock;
            let current_prev_hops = current_candidate.prev_hops.clone();
            let current_prev_distributions = current_candidate.prev_distributions.clone();

            for new_candidate_id in current_node_ref.borrow().neighbor_ids() {
                let new_candidate_ref = self.graph.get_node_ref(new_candidate_id).unwrap();
                if new_candidate_ref.borrow().is_malicious() {
                    continue;
                }
                if let Some(cheapest_edge) = self.cheapest_edge_source(new_candidate_id) {
                    if current_prev_hops.contains(&new_candidate_id) {
                        continue;
                    }
                    let mut new_prev_hops = current_prev_hops.clone();
                    new_prev_hops.insert(current_node_id);

                    let new_hop_dist = estimate_latency_distribution(Rc::clone(&cheapest_edge));
                    let mut new_aggregated_dist = new_hop_dist * 4.0;
                    for d in current_prev_distributions.clone() {
                        new_aggregated_dist = new_aggregated_dist + (d * 4.0);
                    }

                    let cur_pdf = current_aggregated_dist.pdf(meas_time_diff_millis);
                    let new_pdf = new_aggregated_dist.pdf(meas_time_diff_millis);


                    if new_pdf <= cur_pdf {
                        continue;
                    }

                    if let Some(old_candidate) = self.candidate_map.get(&new_candidate_id) {
                        // if we have an old value, only update if new pdf is higher
                        let old_pdf = old_candidate.aggregated_distribution.pdf(meas_time_diff_millis);
                        if new_pdf <= old_pdf {
                            continue;
                        }
                        //info!("old_pdf: {}", old_pdf);
                    }

                    let mut new_prev_distributions = current_prev_distributions.clone();
                    new_prev_distributions.push(new_hop_dist);

                    // FIXME fee calculation is off (as current amount is the amount after deduction)
                    let cheapest_fee = cheapest_edge.borrow().get_fee(current_amount, new_candidate_id).unwrap();

                    let new_amount = current_amount + cheapest_fee;
                    assert!(new_amount <= cheapest_edge.borrow().capacity());

                    let new_time_lock = current_time_lock;

                    let new_candidate = CandidateHop {
                        aggregated_distribution: new_aggregated_dist,
                        current_amount: new_amount,
                        current_time_lock: new_time_lock,
                        prev_hops: new_prev_hops,
                        prev_distributions: new_prev_distributions,
                    };

                    self.candidate_map.insert(new_candidate_id, new_candidate);
                    self.to_visit.push_back(new_candidate_id);
                }
            }
            self.visited.insert(current_node_id);
        }

        // return candidate with highest pdf => MLE 
        // fallback to first spy in worst case
        let mut max_node_ref = self.first_spy_estimate_source();
        let mut max_pdf = 0.0;
        let mut max_dist = CandidateDistribution::new(0.0, 1.0);
        let mut max_prev_hops = HashSet::new();
        let meas_node_id = self.meas_node_ref.borrow().node_id();
        for (n_id, c) in self.candidate_map.clone() {
            if n_id == meas_node_id {
                continue;
            }
            let c_pdf =  c.aggregated_distribution.pdf(meas_time_diff_millis);
            if c_pdf > max_pdf {
                max_pdf = c_pdf;
                max_node_ref = self.graph.get_node_ref(n_id).unwrap();
                max_dist = c.aggregated_distribution.clone();
                max_prev_hops = c.prev_hops.clone();
            }
        }
        info!("Time diff {}, max dist mean {}, pdf {}, prev_hops {:?}", meas_time_diff_millis, max_dist.mean(), max_pdf, max_prev_hops);
        Rc::clone(&max_node_ref)
    }

    pub fn timing_estimate_destination(&mut self, meas_time_diff_millis: f64) -> NodeRef {
        while let Some(current_node_id) = self.next_to_visit() {
            if self.visited.contains(&current_node_id) {
                // skip if we already visited that node
                continue;
            }
            let current_node_ref = self.graph.get_node_ref(current_node_id).unwrap();
            self.current_node_ref = Rc::clone(&current_node_ref);
            let current_candidate = self.candidate_map.get(&current_node_id).unwrap();
            let current_aggregated_dist = current_candidate.aggregated_distribution;
            let current_amount = current_candidate.current_amount;
            let current_remaining_time_lock = current_candidate.current_time_lock;
            let current_prev_hops = current_candidate.prev_hops.clone();
            let current_prev_distributions = current_candidate.prev_distributions.clone();

            for new_candidate_id in current_node_ref.borrow().neighbor_ids() {
                let new_candidate_ref = self.graph.get_node_ref(new_candidate_id).unwrap();
                if new_candidate_ref.borrow().is_malicious() {
                    continue;
                }
                if let Some(cheapest_edge) = self.cheapest_edge_destination(new_candidate_id) {

                    if current_prev_hops.contains(&new_candidate_id) {
                        continue;
                    }
                    let mut new_prev_hops = current_prev_hops.clone();
                    new_prev_hops.insert(current_node_id);

                    let new_hop_dist = estimate_latency_distribution(Rc::clone(&cheapest_edge));
                    let mut new_aggregated_dist = new_hop_dist * 4.0;
                    for d in current_prev_distributions.clone() {
                        new_aggregated_dist = new_aggregated_dist + (d * 4.0);
                    }

                    let cur_pdf = current_aggregated_dist.pdf(meas_time_diff_millis);
                    let new_pdf = new_aggregated_dist.pdf(meas_time_diff_millis);


                    if new_pdf <= cur_pdf {
                        continue;
                    }

                    let mut new_prev_distributions = current_prev_distributions.clone();
                    new_prev_distributions.push(new_hop_dist);

                    if let Some(old_candidate) = self.candidate_map.get(&new_candidate_id) {
                        // if we have an old value, only update if new pdf is higher
                        let old_pdf = old_candidate.aggregated_distribution.pdf(meas_time_diff_millis);
                        if new_pdf <= old_pdf {
                            continue;
                        }
                    }

                    let cheapest_fee = cheapest_edge.borrow().get_fee(current_amount, current_node_id).unwrap();

                    let new_amount = current_amount - cheapest_fee;
                    assert!(new_amount <= cheapest_edge.borrow().capacity());

                    let cheapest_timelock = cheapest_edge.borrow().get_time_lock_delta(current_node_id).unwrap();
                    if cheapest_timelock > current_remaining_time_lock {
                        continue;
                    }
                    let new_remaining_time_lock = current_remaining_time_lock-cheapest_timelock;

                    let new_candidate = CandidateHop {
                        aggregated_distribution: new_aggregated_dist,
                        current_amount: new_amount,
                        current_time_lock: new_remaining_time_lock,
                        prev_hops: new_prev_hops,
                        prev_distributions: new_prev_distributions,
                    };

                    self.candidate_map.insert(new_candidate_id, new_candidate);
                    self.to_visit.push_back(new_candidate_id);
                }
            }
            self.visited.insert(current_node_id);
        }

        // return candidate with highest pdf => MLE 
        // fallback to first spy in worst case
        let mut max_node_ref = self.first_spy_estimate_destination();
        let mut max_pdf = 0.0;
        let mut max_dist = CandidateDistribution::new(0.0, 1.0);
        let mut max_prev_hops = HashSet::new();
        let meas_node_id = self.meas_node_ref.borrow().node_id();
        for (n_id, c) in self.candidate_map.clone() {
            if n_id == meas_node_id {
                continue;
            }
            let c_pdf =  c.aggregated_distribution.pdf(meas_time_diff_millis);
            if c_pdf > max_pdf {
                max_pdf = c_pdf;
                max_node_ref = self.graph.get_node_ref(n_id).unwrap();
                max_dist = c.aggregated_distribution.clone();
                max_prev_hops = c.prev_hops.clone();
            }
        }
        info!("Time diff {}, max dist mean {}, pdf {}, prev_hops {:?}", meas_time_diff_millis, max_dist.mean(), max_pdf, max_prev_hops);
        Rc::clone(&max_node_ref)
    }

    fn next_to_visit(&mut self) -> Option<NodeId> {
        self.to_visit.pop_front()
    }

    fn cheapest_edge_source(&self, to_node: NodeId) -> Option<EdgeRef> {
        let current_node_id = self.current_node_ref.borrow().node_id();
        if let Some(current_hop) = self.candidate_map.get(&current_node_id) {
            let current_amount = current_hop.current_amount;

            let candidate_edges = self.current_node_ref.borrow().edges_to_neighbor(to_node);
            let mut cheapest_price = EdgeWeight::Infinity; 
            let mut cheapest_edge: Option<EdgeRef> = None;
            for e in candidate_edges {
                let fee = e.borrow().get_fee(current_amount, to_node).unwrap();
                if current_amount+fee > e.borrow().capacity() {
                    continue;
                }

                let time_lock_delta = e.borrow().get_time_lock_delta(to_node).unwrap();
                let weight = edge_weight(current_amount, fee, time_lock_delta);
                if weight < cheapest_price {
                    cheapest_price = weight;
                    cheapest_edge = Some(Rc::clone(&e));
                }
            }

            return cheapest_edge;
        } 
        None
    }

    fn cheapest_edge_destination(&self, to_node: NodeId) -> Option<EdgeRef> {
        let current_node_id = self.current_node_ref.borrow().node_id();
        if let Some(current_hop) = self.candidate_map.get(&current_node_id) {
            let current_amount = current_hop.current_amount;
            let current_remaining_time_lock = current_hop.current_time_lock;

            let candidate_edges = self.current_node_ref.borrow().edges_to_neighbor(to_node);
            let mut cheapest_price = EdgeWeight::Infinity; 
            let mut cheapest_edge: Option<EdgeRef> = None;
            for e in candidate_edges {
                let fee = e.borrow().get_fee(current_amount, current_node_id).unwrap();
                if fee >= current_amount {
                    continue;
                }
                if current_amount-fee > e.borrow().capacity() {
                    continue;
                }

                let time_lock_delta = e.borrow().get_time_lock_delta(current_node_id).unwrap();
                if current_remaining_time_lock < time_lock_delta {
                    continue;
                }
                let weight = edge_weight(current_amount, fee, time_lock_delta);
                if weight < cheapest_price {
                    cheapest_price = weight;
                    cheapest_edge = Some(Rc::clone(&e));
                }
            }

            return cheapest_edge;
        } 
        None
    }
}

pub fn estimate_latency_distribution(edge: EdgeRef) -> CandidateDistribution {
    let mut probes = Vec::new();
    for _ in 0..100 {
        let probe = edge.borrow().latency_dist().sample() as f64;
        probes.push(probe);
    }
    let new_mean = probes.mean();
    let mut new_std_dev = probes.std_dev();
    if new_std_dev == 0.0 {
        new_std_dev = 1.0;
    }

    CandidateDistribution::new(new_mean, new_std_dev)
}
