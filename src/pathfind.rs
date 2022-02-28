use crate::graph::{Graph, NodeId, Path, EdgeRef};
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::collections::HashSet;
use std::ops::{Add, Sub};

#[allow(unused_imports)] 
use log::{info,debug,trace};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
pub enum EdgeWeight { 
    Weight(u64), 
    Infinity 
}

impl Add for EdgeWeight {
    type Output = EdgeWeight;
    fn add(self, other: EdgeWeight) -> Self {
        match (self,other) {
            (EdgeWeight::Weight(s), EdgeWeight::Weight(o)) => EdgeWeight::Weight(s+o),
            _ => EdgeWeight::Infinity
        }
    }
}

impl Sub for EdgeWeight {
    type Output = EdgeWeight;
    fn sub(self, other: EdgeWeight) -> Self {
        match (self,other) {
            (EdgeWeight::Weight(s), EdgeWeight::Weight(o)) => {
                if o > s {
                    return EdgeWeight::Weight(0);
                }
                EdgeWeight::Weight(s-o)
            },
            _ => EdgeWeight::Infinity
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CandidatePath {
    path: Path,
    aggregated_weight: EdgeWeight,
    aggregated_amount: u64,
    aggregated_time: u16,
}

impl CandidatePath {
    pub fn new(source_id: NodeId, destination_id: NodeId, amount: u64) -> Self {
        let path = Path::new(source_id, destination_id);
        let aggregated_weight = EdgeWeight::Weight(0);
        let aggregated_amount = amount;
        let aggregated_time = 0;
        Self { path, aggregated_weight, aggregated_amount, aggregated_time }
    }
}

pub struct PathFinder {
    distance_map: BTreeMap<EdgeWeight, VecDeque<NodeId>>,
    candidate_map: BTreeMap<NodeId, CandidatePath>,
    visited: HashSet<NodeId>,
    source_node: NodeId,
    destination_node: NodeId,
    current_node: NodeId,
    max_time_lock_delta: u16,
    graph: Box<Graph>,
}

impl PathFinder {
    pub fn new(source_node: NodeId, destination_node: NodeId, amount: u64, max_time_lock_delta: u16, graph: Box<Graph>) -> Self {
        let mut distance_map: BTreeMap<EdgeWeight, VecDeque<NodeId>> = BTreeMap::new();
        let mut candidate_map: BTreeMap<NodeId, CandidatePath> = BTreeMap::new();
        let visited = HashSet::new();
        let current_node = destination_node;
        let mut candidate_list = VecDeque::new();
        candidate_list.push_back(current_node);
        distance_map.insert(EdgeWeight::Weight(0), candidate_list);
        let candidate = CandidatePath::new(source_node, destination_node, amount);
        candidate_map.insert(current_node, candidate);
        Self { distance_map, candidate_map, visited, source_node, current_node, destination_node, max_time_lock_delta, graph }
    }

    // find_path returns a path, the aggregated amount, and the necessary lock time 
    pub fn find_path(&mut self) -> Option<(Path, u64, u16)> {
        while let Some(current_node) = self.next_to_visit() {
            if self.visited.contains(&current_node) {
                // skip if we already visited that node
                continue;
            }
            self.current_node = current_node;
            if let Some(current_node_ref) = self.graph.get_node_ref(current_node) {

                let current_candidate = self.candidate_map.get(&current_node).unwrap();
                let current_path = current_candidate.path.clone();
                let current_aggregated_weight = current_candidate.aggregated_weight;
                let current_aggregated_amount = current_candidate.aggregated_amount;
                let current_aggregated_time = current_candidate.aggregated_time;

                for neighbor in current_node_ref.borrow().neighbor_ids() {
                    if let Some((cheapest_weight, cheapest_edge)) = self.cheapest_edge(neighbor) {
                        // as we're discovering the path from destination to source, we get the fee
                        // from our 'neighbor'
                        let cheapest_fee = cheapest_edge.borrow().get_fee(current_aggregated_amount, neighbor).unwrap();

                        let cheapest_timelock = cheapest_edge.borrow().get_time_lock_delta(neighbor).unwrap();

                        if let Some(old_neighbor_candidate) = self.candidate_map.get(&neighbor) {
                            // if we have an old value, only update if new weight is lower than old. 
                            if cheapest_weight + current_aggregated_weight >= old_neighbor_candidate.aggregated_weight {
                                continue;
                            }
                        }

                        // update distance and candidate maps
                        let mut new_path = current_path.clone();
                        //println!("Path: {:?}", new_path);
                        //println!("Cheapest: {:?}", cheapest_edge);
                        //println!();
                        new_path.add_hop(cheapest_edge.clone(), current_aggregated_amount, current_aggregated_time).unwrap();
                        let new_aggregated_weight = current_aggregated_weight + cheapest_weight;
                        let new_aggregated_amount = current_aggregated_amount + cheapest_fee;
                        let new_aggregated_time = current_aggregated_time + cheapest_timelock;
                        assert!(new_aggregated_amount <= cheapest_edge.borrow().capacity());
                        let new_candidate = CandidatePath {
                            path: new_path,
                            aggregated_weight: new_aggregated_weight,
                            aggregated_amount: new_aggregated_amount,
                            aggregated_time: new_aggregated_time,
                        };

                        self.candidate_map.insert(neighbor, new_candidate);
                        self.set_distance(neighbor, new_aggregated_weight);
                    } 
                }

                // at this point, we would mark the source_node as visited, hence we're done
                if current_node == self.source_node {
                    let final_path = self.candidate_map.get(&self.source_node).unwrap().path.clone(); 
                    if final_path.len() > 0 {
                        assert!(final_path.first_edge().unwrap().borrow().node_in_edge(self.source_node));
                        assert!(final_path.last_edge().unwrap().borrow().node_in_edge(self.destination_node));
                    }
                    let final_amount = self.candidate_map.get(&self.source_node).unwrap().aggregated_amount;
                    let final_lock_time = self.candidate_map.get(&self.source_node).unwrap().aggregated_time;
                    return Some((final_path, final_amount, final_lock_time));
                }
                self.visited.insert(current_node);
            } else {
                return None
            }
        }
        None
    }

    fn set_distance(&mut self, node: NodeId, distance: EdgeWeight) {
        let result = self.distance_map.get_mut(&distance);
        match result {
            Some(list) => {
                list.push_back(node);
            },
            None => {
                let mut list = VecDeque::new();
                list.push_back(node);
                self.distance_map.insert(distance, list);
            },
        }
    }

    fn next_to_visit(&mut self) -> Option<NodeId> {
        let mut result = None;

        let mut done_weight = EdgeWeight::Infinity;

        if let Some((candidate_weight, candidate_list)) = self.distance_map.iter_mut().next() {
            result = candidate_list.pop_front();

            if candidate_list.is_empty() {
                done_weight = *candidate_weight
            }
        } 
        if done_weight != EdgeWeight::Infinity {
            self.distance_map.remove(&done_weight);
        }

        result
    }

    // cheapest_edge returns the edge with the minimum weight between a pair of connected nodes. This considers our multigraph, and allows
    // us to otherwise use standard Dijkstra.
    fn cheapest_edge(&self, to_node: NodeId) -> Option<(EdgeWeight, EdgeRef)> {
        if let Some(candidate_path) = self.candidate_map.get(&self.current_node) {
            let amount = candidate_path.aggregated_amount;
            let cur_max_time_lock = self.max_time_lock_delta - candidate_path.aggregated_time;

            if let Some(current_node_ref) = self.graph.get_node_ref(self.current_node) {
                let candidate_edges = current_node_ref.borrow().edges_to_neighbor(to_node);
                let mut cheapest_price = EdgeWeight::Infinity; 
                let mut cheapest_edge: Option<(EdgeWeight, EdgeRef)> = None;
                for e in candidate_edges {
                    // as we're discovering the path from destination to source, we get the fee
                    // from our 'to_node'
                    let fee = e.borrow().get_fee(amount, to_node).unwrap();
                    if amount+fee > e.borrow().capacity() {
                        continue;
                    }

                    if self.current_node == self.source_node || to_node == self.source_node {
                        // we know channel balances for each edge adjacent to the source node
                        let balance = e.borrow().get_balance(to_node).unwrap();
                        if amount+fee > balance {
                            info!("skipping because of balance: {}", balance);
                            continue;
                        } 
                    }

                    let time_lock_delta = e.borrow().get_time_lock_delta(to_node).unwrap();
                    if cur_max_time_lock < time_lock_delta {
                        continue;
                    }
                    let weight = edge_weight(amount, fee, time_lock_delta);
                    if weight < cheapest_price {
                        cheapest_price = weight;
                        cheapest_edge = Some((weight, e.clone()));
                    }
                }

                return cheapest_edge;
            } 
        } 
        None
    }

}

pub fn edge_weight(locked_amount: u64, fee: u64, time_lock_delta: u16) -> EdgeWeight {
    let risk_factor_billionths = 15;
    // From LND (pathfind.go:237):
    // "edgeWeight computes the weight of an edge. This value is used when searching
    // for the shortest path within the channel graph between two nodes. Weight is
    // is the fee itself plus a time lock penalty added to it. This benefits
    // channels with shorter time lock deltas and shorter (hops) routes in general.
    // RiskFactor controls the influence of time lock on route selection. This is
    // currently a fixed value, but might be configurable in the future."
    // and
    // "timeLockPenalty is the penalty for the time lock delta of this channel.
    // It is controlled by RiskFactorBillionths and scales proportional
    // to the amount that will pass through channel. Rationale is that it if
    // a twice as large amount gets locked up, it is twice as bad."
    let time_lock_penalty = locked_amount * time_lock_delta as u64* risk_factor_billionths / 1000000000;
    return EdgeWeight::Weight(fee+time_lock_penalty);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edgeweight_ord_works() {
        for _ in 0..100 {
            let rand: u64 = rand::random();
            assert!(EdgeWeight::Infinity > EdgeWeight::Weight(rand));
        }
    }

    #[test]
    fn edgeweight_add_works() {
        assert_eq!(EdgeWeight::Weight(0) + EdgeWeight::Weight(5), EdgeWeight::Weight(5));
        assert_eq!(EdgeWeight::Weight(50) + EdgeWeight::Weight(5), EdgeWeight::Weight(55));
        assert_eq!(EdgeWeight::Infinity + EdgeWeight::Infinity, EdgeWeight::Infinity);
    }

    #[test]
    fn edgeweight_sub_works() {
        assert_eq!(EdgeWeight::Weight(0) - EdgeWeight::Weight(5), EdgeWeight::Weight(0));
        assert_eq!(EdgeWeight::Weight(50) - EdgeWeight::Weight(5), EdgeWeight::Weight(45));
        assert_eq!(EdgeWeight::Infinity - EdgeWeight::Infinity, EdgeWeight::Infinity);
    }
}
