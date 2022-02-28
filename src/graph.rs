use std::rc::Rc;
use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::VecDeque;
use itertools::Itertools;
use std::process;
use std::fmt;
use rand::Rng;
use regex::Regex;
use std::fs::File; 
use std::io::prelude::*;


use std::cmp::Ordering;


#[allow(unused_imports)] 
use log::{info,debug,trace};

use lngraphparser as lngp;

use crate::CONFIG;
use crate::RNG;
use crate::geo::Region;
use crate::geo::GeoReader;
use crate::latency::{LatencyModel, LatencyDistributionRef};
use crate::util;


pub type NodeId = u32;
pub type EdgeId = u32;
pub type NodeRef = Rc<RefCell<Node>>;
pub type EdgeRef = Rc<RefCell<Edge>>;
pub type ChannelStateRef = Rc<RefCell<ChannelState>>;
pub type ChannelStateId = u32;
pub type PathRef = Rc<RefCell<Path>>;

#[derive(Debug, Clone)]
pub struct Graph {
    nodes: HashMap<NodeId, NodeRef>,
    edges: HashMap<EdgeId, EdgeRef>,
    latency_distributions: HashMap<(NodeId, NodeId), LatencyDistributionRef>,
    max_capacity: u64,
    avg_capacity: u64,
    total_capacity: u64,
    lnbig_nodes: Vec<NodeId>,
    most_central_nodes: Vec<NodeId>,
}

impl Graph {
    pub fn from_json_str(json_data: &String) -> Self {
        let mut nodes = HashMap::new();
        let mut edges = HashMap::new();
        let mut latency_distributions: HashMap<(NodeId, NodeId), LatencyDistributionRef> = HashMap::new();
        let mut max_capacity = 0;
        let mut avg_capacity = 0;
        let mut total_capacity = 0;
        let mut lnbig_nodes = Vec::new();

        let latency_model = LatencyModel::new();

        let geo_reader = GeoReader::try_new(CONFIG.read().unwrap().geoip2_db_path()).unwrap_or_else(|| {
            eprintln!("Could not open geodb!");
            process::exit(-1);
        });

        if let Ok(parsed_graph) = lngp::from_json_str(&json_data) {

            let num_parsed = parsed_graph.nodes.len();
            // since we don't need the pubkeys, we don't add them to our node objects. however,
            // during initialization we remember which pubkey / channel_id mapped to which node id / edge id.
            let mut pubkey_map: HashMap<String, NodeId> = HashMap::new();
            let mut channel_id_map: HashMap<String, EdgeId> = HashMap::new();
            let mut cur_node_id = 0;
            let mut cur_edge_id = 0;

            for n in parsed_graph.nodes {
                let alias = n.alias.clone();
                pubkey_map.insert(n.pub_key.clone(), cur_node_id);
                let region = geo_reader.get_region(n);
                let node_ref = Rc::new(RefCell::new(Node::new(cur_node_id, region)));
                nodes.insert(cur_node_id, Rc::clone(&node_ref));

                // check if LNBIG node:
                let re = Regex::new(r"LNBIG").unwrap();
                if re.is_match(&alias) {
                    lnbig_nodes.push(cur_node_id)
                }

                cur_node_id += 1;
            }


            for e in parsed_graph.edges {
                if let Some(node1_id) = pubkey_map.get(&e.node1_pub) {
                    if let Some(node2_id) = pubkey_map.get(&e.node2_pub) {
                        // we've seen the pubkey
                        if let Some(node1) = nodes.get(node1_id) {
                            if let Some(node2) = nodes.get(node2_id) {
                                // we've added the nodes before
                                let region1 = node1.borrow().region;
                                let region2 = node2.borrow().region;

                                let latency_key = util::ordered_tuple_key(*node1_id, *node2_id);
                                let latency_dist: LatencyDistributionRef = if let Some(prior_latency_dist) = latency_distributions.get(&latency_key) {
                                    Rc::clone(&prior_latency_dist)
                                } else {
                                    let new_latency_model = Rc::new(latency_model.rand_lat_dist(region1, region2).unwrap());
                                    latency_distributions.insert(latency_key, Rc::clone(&new_latency_model));
                                    Rc::clone(&new_latency_model)
                                };


                                let mut node1_time_lock_delta: u16 = CONFIG.read().unwrap().default_time_lock_delta();
                                let mut node1_fee_base_msat: u64 = CONFIG.read().unwrap().default_fee_base_msat();
                                let mut node1_fee_rate_milli_msat: u64 = CONFIG.read().unwrap().default_fee_rate_milli_msat();
                                let mut node2_time_lock_delta: u16 = CONFIG.read().unwrap().default_time_lock_delta();
                                let mut node2_fee_base_msat: u64 = CONFIG.read().unwrap().default_fee_base_msat();
                                let mut node2_fee_rate_milli_msat: u64 = CONFIG.read().unwrap().default_fee_rate_milli_msat();

                                if let Some(node1_policy) = e.node1_policy {
                                    node1_time_lock_delta = node1_policy.time_lock_delta;
                                    node1_fee_base_msat = node1_policy.fee_base_msat;
                                    node1_fee_rate_milli_msat = node1_policy.fee_rate_milli_msat; 
                                } 

                                if let Some(node2_policy) = e.node2_policy {
                                    node2_time_lock_delta = node2_policy.time_lock_delta;
                                    node2_fee_base_msat = node2_policy.fee_base_msat;
                                    node2_fee_rate_milli_msat = node2_policy.fee_rate_milli_msat; 
                                } 

                                // We're getting capacity as sats, but handle everything as msats
                                let capacity_msats: u64 = e.capacity as u64 * 1000;
                                total_capacity += capacity_msats;
                                max_capacity = std::cmp::max(max_capacity, capacity_msats);
                                let edge = Rc::new(RefCell::new(Edge::new(cur_edge_id, 
                                                                          capacity_msats,
                                                                          *node1_id,
                                                                          *node2_id,
                                                                          latency_dist,
                                                                          node1_time_lock_delta,
                                                                          node2_time_lock_delta,
                                                                          node1_fee_base_msat,
                                                                          node2_fee_base_msat,
                                                                          node1_fee_rate_milli_msat, 
                                                                          node2_fee_rate_milli_msat
                                                                         )));

                                channel_id_map.insert(e.channel_id, cur_edge_id);
                                edges.insert(cur_edge_id, edge.clone());
                                node1.borrow_mut().add_edge(Rc::clone(&edge));
                                node2.borrow_mut().add_edge(Rc::clone(&edge));
                                cur_edge_id += 1;
                            }
                        }

                    }

                }
            }


            avg_capacity = total_capacity/edges.len() as u64;
            info!("total number of nodes: {}, after geo: {}", num_parsed, nodes.len());
            info!("max capacity: {}, avg. capacity: {}, total capacity: {}", max_capacity, avg_capacity, total_capacity);
        }
        let most_central_nodes = read_most_central();

        Self {nodes, edges, latency_distributions, max_capacity, avg_capacity, total_capacity, most_central_nodes, lnbig_nodes }
    }

    pub fn num_nodes(&self) -> usize {
        self.nodes.len()
    }

    pub fn num_edges(&self) -> usize {
        self.edges.len()
    }

    pub fn max_capacity(&self) -> u64 {
        self.max_capacity
    }

    pub fn avg_capacity(&self) -> u64 {
        self.avg_capacity
    }

    pub fn total_capacity(&self) -> u64 {
        self.total_capacity
    }

    pub fn get_node_ref(&self, node_id: NodeId) -> Option<NodeRef> {
        match self.nodes.get(&node_id) {
            Some(n_ref) => Some(Rc::clone(&n_ref)),
            None => None,
        }
    }

    pub fn get_m_most_central_nodes(&self, num_nodes: u32) -> Vec<NodeId> {
        let mut central_nodes = Vec::new();
        for i in 0..num_nodes {
            let node = self.most_central_nodes[i as usize];
            central_nodes.push(node);
        }
        central_nodes
    }

    pub fn get_lnbig_nodes(&self) -> Vec<NodeId> {
        self.lnbig_nodes.clone()
    }

    pub fn get_random_node(&self) -> Option<NodeRef> {
        let mut rng = RNG.lock().unwrap();
        let min: NodeId = 0;
        let max: NodeId = self.nodes.len() as u32;
        let rand_index = (*rng).gen_range(min, max);
        match self.nodes.get(&rand_index) {
            Some(n_ref) => Some(Rc::clone(&n_ref)),
            None => None,
        }
    }

    pub fn get_m_random_nodes(&self, num_nodes: u32) -> Vec<NodeId> {
        let mut random_nodes = Vec::new();
        let mut rng = RNG.lock().unwrap();
        let min: NodeId = 0;
        let max: NodeId = self.nodes.len() as u32;
        for _ in 0..num_nodes {
            let rand_index = (*rng).gen_range(min, max);
            random_nodes.push(rand_index);
        }
        random_nodes
    }

    pub fn get_edge(&self, edge_id: EdgeId) -> Option<EdgeRef> {
        match self.edges.get(&edge_id) {
            Some(e_ref) => Some(Rc::clone(&e_ref)),
            None => None,
        }
    }
    //pub fn remove_node(&mut self, node_id: NodeId) {
    //    match self.nodes.get(&node_id) {
    //        Some(n_ref) => {
    //            // clear references in graph edges
    //            for (_, e_vec) in n_ref.borrow().edges() {
    //                for e in e_vec {
    //                    self.edges.remove(&e.borrow().edge_id);
    //                }
    //            }

    //            // clear references in neighbor edges
    //            for neighbor in n_ref.borrow_mut().neighbor_ids() {
    //                match self.get_node(neighbor) {
    //                    Some(neighbor_ref) => {
    //                        neighbor_ref.borrow_mut().remove_neighbor(node_id);
    //                        n_ref.borrow_mut().remove_neighbor(neighbor);
    //                    },
    //                    None => continue,
    //                }
    //            }

    //            // remove node
    //            self.nodes.remove(&node_id);
    //        },
    //        None => return
    //    }
    //}
}


#[derive(Debug)]
pub struct Node {
    // public info:
    node_id: NodeId,
    region: Region,
    edges: HashMap<NodeId, Vec<EdgeRef>>,
    malicious: bool,
}

impl Node {
    pub fn new(node_id: NodeId, region: Region) -> Self {
        let edges = HashMap::new();
        let malicious =  false;
        Self { node_id, region, edges, malicious }
    }

    pub fn add_edge(&mut self, e_ref: EdgeRef) {
        let node1_id = e_ref.borrow().node1_id;
        let node2_id = e_ref.borrow().node2_id;

        let other_node = if node1_id == self.node_id {
            node2_id 
        } else {
            node1_id
        };

        let edges_to_neighbor = self.edges.entry(other_node).or_insert(Vec::new());
        edges_to_neighbor.push(e_ref);
    }

    pub fn remove_neighbor(&mut self, node_id: NodeId) {
        let edges_to_neighbor = self.edges.entry(node_id).or_insert(Vec::new());
        edges_to_neighbor.clear();
    }

    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    pub fn neighbor_ids(&self) -> Vec<NodeId> {
        self.edges.keys().cloned().collect()
    }

    pub fn has_edge_to(&self, other_node: NodeId) -> bool {
        self.edges.contains_key(&other_node)
    }

    pub fn edges(&self) -> HashMap<NodeId,Vec<EdgeRef>> {
        self.edges.clone()
    }

    pub fn edges_to_neighbor(&self, other_node: NodeId) -> Vec<EdgeRef> {
        match self.edges.get(&other_node) {
            Some(edges) => (*edges).clone(),
            None => Vec::new(),
        }
    }

    pub fn set_malicious(&mut self) {
        self.malicious = true;
    }

    pub fn is_malicious(&self) -> bool {
        self.malicious
    }
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.node_id)
    }
}

impl PartialEq for Node {
    fn eq(&self, other: &Self) -> bool {
        self.node_id == other.node_id
    }
}

impl Eq for Node {}

#[derive(Debug)]
pub struct Edge
{
    // public info:
    edge_id: EdgeId,
    capacity: u64,
    node1_id: NodeId,
    node2_id: NodeId,
    latency_dist: LatencyDistributionRef,
    channel_state: ChannelStateRef,
    node1_time_lock_delta: u16,
    node2_time_lock_delta: u16,
    node1_fee_base_msat: u64,
    node1_fee_rate_milli_msat: u64,
    node2_fee_base_msat: u64,
    node2_fee_rate_milli_msat: u64,
}

impl Edge {
    pub fn new(edge_id: EdgeId, 
               capacity: u64,
               node1_id: NodeId,
               node2_id: NodeId,
               latency_dist: LatencyDistributionRef,
               node1_time_lock_delta: u16,
               node2_time_lock_delta: u16,
               node1_fee_base_msat: u64,
               node2_fee_base_msat: u64,
               node1_fee_rate_milli_msat: u64, 
               node2_fee_rate_milli_msat: u64
              ) -> Self {
        let state_id = 0;
        let node1_balance = capacity/2;
        let node2_balance = capacity-node1_balance;
        assert_eq!(capacity, node1_balance+node2_balance);
        let channel_state = Rc::new(RefCell::new(ChannelState::new(state_id, node1_id, node2_id, node1_balance, node2_balance)));
        Self { 
            edge_id,
            capacity,
            node1_id,
            node2_id,
            latency_dist,
            channel_state,
            node1_time_lock_delta,
            node2_time_lock_delta,
            node1_fee_base_msat,
            node2_fee_base_msat,
            node1_fee_rate_milli_msat,
            node2_fee_rate_milli_msat,
        }
    }

    pub fn edge_id(&self) -> EdgeId {
        self.edge_id
    }

    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    pub fn node1_id(&self) -> NodeId {
        self.node1_id
    }

    pub fn node2_id(&self) -> NodeId {
        self.node2_id
    }

    pub fn neighbor_id(&self, node_id: NodeId) -> Option<NodeId> {
        if self.node1_id == node_id {
            return Some(self.node2_id);
        }

        if self.node2_id == node_id {
            return Some(self.node1_id);
        }

        None
    }

    pub fn node_in_edge(&self, node_id: NodeId) -> bool {
        if node_id == self.node1_id || node_id == self.node2_id {
            return true;
        }
        false
    }

    pub fn get_fee(&self, amount: u64, from: NodeId) -> Option<u64> {
        let base = if from == self.node1_id {
            self.node1_fee_base_msat
        } else if from == self.node2_id {
            self.node2_fee_base_msat
        } else {
            return None;
        };

        let rate = if from == self.node1_id {
            self.node1_fee_rate_milli_msat
        } else if from == self.node2_id {
            self.node2_fee_rate_milli_msat
        } else {
            return None;
        };

        // BOLT07: fee_base_msat + ( amount_to_forward * fee_proportional_millionths / 1000000 )
        //println!("Amount: {}, base: {}, rate: {}", amount, base, rate);
        let fee = base + (amount * rate / 1000);
        Some (fee)
    }

    pub fn get_time_lock_delta(&self, from: NodeId) -> Option<u16> {
        let time_lock_delta = if from == self.node1_id {
            self.node1_time_lock_delta
        } else if from == self.node2_id {
            self.node2_time_lock_delta
        } else {
            return None;
        };

        Some(time_lock_delta)
    }

    pub fn get_balance(&self, from: NodeId) -> Option<u64> {
        let balance = if from == self.node1_id {
            self.channel_state.borrow().node1_balance
        } else if from == self.node2_id {
            self.channel_state.borrow().node2_balance
        } else {
            return None;
        };

        Some(balance)
    }

    pub fn latency_dist(&self) -> LatencyDistributionRef {
        Rc::clone(&self.latency_dist)
    }

    pub fn channel_state(&self) -> ChannelStateRef {
        Rc::clone(&self.channel_state)
    }

    pub fn update_channel_state(&mut self, new_state: ChannelStateRef) -> bool {
        let edge_state = self.channel_state();

        if new_state <= edge_state {
            return false;
        }
        self.channel_state = new_state;
        return true;
    }

    pub fn update_is_valid(&self, new_state: ChannelStateRef) -> bool {
        if new_state <= self.channel_state {
            return false;
        }
        return true;
    }


}

impl PartialEq for Edge {
    fn eq(&self, other: &Self) -> bool {
        self.edge_id == other.edge_id
    }
}

impl Eq for Edge {}

impl fmt::Display for Edge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {})", self.node1_id, self.node2_id)
    }
}

#[derive(Debug)]
pub struct ChannelState {
    state_id: ChannelStateId,
    node1_id: NodeId,
    node2_id: NodeId,
    node1_balance: u64,
    node2_balance: u64,
    node1_acked: bool,
    node2_acked: bool,
    node1_committed: bool,
    node2_committed: bool,
}

impl ChannelState {
    pub fn new(state_id: u32, node1_id: NodeId, node2_id: NodeId, node1_balance: u64, node2_balance: u64) -> Self {
        Self {
            state_id: state_id,
            node1_id: node1_id,
            node2_id: node2_id,
            node1_balance: node1_balance,
            node2_balance: node2_balance,
            node1_acked: false,
            node2_acked: false,
            node1_committed: false,
            node2_committed: false,
        }
    }
    pub fn state_id(&self) -> ChannelStateId {
        self.state_id
    }

    pub fn node1_id(&self) -> NodeId {
        self.node1_id
    }

    pub fn node2_id(&self) -> NodeId {
        self.node2_id
    }

    pub fn node1_balance(&self) -> u64 {
        self.node1_balance
    }

    pub fn node2_balance(&self) -> u64 {
        self.node2_balance
    }

    pub fn state_is_committed(&self, node: NodeRef) -> bool {
        let node1_id = self.node1_id;
        if node.borrow().node_id == node1_id {
            self.node1_committed
        } else {
            self.node2_committed
        }
    }

    pub fn state_is_acked(&self, node: NodeRef) -> bool {
        let node1_id = self.node1_id;
        if node.borrow().node_id == node1_id {
            self.node1_acked
        } else {
            self.node2_acked
        }
    }

    pub fn set_state_committed(&mut self, node: NodeRef) {
        let node1_id = self.node1_id;
        if node.borrow().node_id == node1_id {
            self.node1_committed = true;
        } else {
            self.node2_committed = true;
        }
    }

    pub fn set_state_acked(&mut self, node: NodeRef) {
        let node1_id = self.node1_id;
        if node.borrow().node_id == node1_id {
            self.node1_acked = true;
        } else {
            self.node2_acked = true;
        }
    }
}

impl PartialEq for ChannelState {
    fn eq(&self, other: &Self) -> bool {
        self.state_id == other.state_id
    }
}

impl Eq for ChannelState {}

impl Ord for ChannelState {
    fn cmp(&self, other: &Self) -> Ordering {
        self.state_id.cmp(&other.state_id)
    }
}

impl PartialOrd for ChannelState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Path {
    source_id: NodeId, 
    destination_id: NodeId,
    edges: VecDeque<EdgeRef>,
    hop_amounts_to_forward: HashMap<EdgeId, u64>,
    hop_remaining_times: HashMap<EdgeId, u16>,
    current_index: Option<usize>, 
}

impl Path {
    pub fn new(source_id: NodeId, destination_id: NodeId) -> Self {
        let edges = VecDeque::new();
        let hop_amounts_to_forward = HashMap::new();
        let hop_remaining_times = HashMap::new();
        let current_index = None;
        Self { source_id, destination_id, edges, hop_amounts_to_forward, hop_remaining_times, current_index }
    }

    pub fn add_hop(&mut self, new_edge: EdgeRef, amount_to_forward: u64, remaining_time: u16) -> Result<(), &str> {
        // new hops are added at the front, as we build the path from destination to source
        let new_id = new_edge.borrow().edge_id;
        match self.edges.front() {
            Some(first_edge) => {
                // check we have a connecting path
                if first_edge.borrow().node1_id == new_edge.borrow().node1_id || 
                    first_edge.borrow().node1_id == new_edge.borrow().node2_id || 
                        first_edge.borrow().node2_id == new_edge.borrow().node1_id || 
                        first_edge.borrow().node2_id == new_edge.borrow().node2_id {
                            self.edges.push_front(new_edge);
                            self.hop_amounts_to_forward.insert(new_id, amount_to_forward);
                            self.hop_remaining_times.insert(new_id, remaining_time);
                            Ok(())
                        } else {
                            Err("Tried to add non-connecting edge")
                        }
            },
            None => {
                // If empty, just push
                self.edges.push_front(new_edge);
                self.hop_amounts_to_forward.insert(new_id, amount_to_forward);
                self.hop_remaining_times.insert(new_id, remaining_time);
                self.current_index = Some(0);
                Ok(())
            }
        }
    }

    pub fn len(&self) -> usize {
        self.edges.len()
    }

    pub fn cur_edge(&self) -> Option<EdgeRef> {
        if self.edges.is_empty() {
            return None;
        }

        if let Some(index) = self.current_index {
            if let Some(edge_ref) = self.edges.get(index) {
                return Some(edge_ref.clone());
            }
        }
        None
    }

    pub fn peek_next_edge(&self) -> Option<EdgeRef> {
        if self.edges.is_empty() {
            return None;
        }

        if let Some(cur_index) = self.current_index {
            let next_index = cur_index + 1;
            if let Some(edge_ref) = self.edges.get(next_index) {
                return Some(Rc::clone(&edge_ref));
            }
        }
        None
    }

    pub fn peek_prev_edge(&self) -> Option<EdgeRef> {
        if self.edges.is_empty() {
            return None;
        }

        if let Some(cur_index) = self.current_index {
            if cur_index == 0 {
                return None;
            }
            let next_index = cur_index - 1;
            if let Some(edge_ref) = self.edges.get(next_index) {
                return Some(Rc::clone(&edge_ref));
            }
        }
        None
    }

    pub fn first_edge(&self) -> Option<EdgeRef> {
        if let Some(edge_ref) = self.edges.front() {
            return Some(edge_ref.clone());
        }
        None
    }

    pub fn last_edge(&self) -> Option<EdgeRef> {
        if let Some(edge_ref) = self.edges.back() {
            return Some(edge_ref.clone());
        }
        None
    }

    pub fn walk_forward(&mut self) {
        if self.current_index == Some(self.edges.len()-1) {
            return;
        }
        if let Some(old_index) = self.current_index {
            let new_index = old_index + 1;
            if self.edges.get(new_index).is_some() {
                self.current_index = Some(new_index);
            }
        }
    }

    pub fn walk_backward(&mut self) {
        if self.current_index == Some(0) {
            return;
        }
        if let Some(old_index) = self.current_index {
            let new_index = old_index - 1;
            if self.edges.get(new_index).is_some() {
                self.current_index = Some(new_index);
            }
        }
    }

    pub fn get_hop_amount_to_forward(&self, edge_id: EdgeId) -> Option<u64> {
        if let Some(res) = self.hop_amounts_to_forward.get(&edge_id) {
            return Some(*res);
        }
        None
    }

    pub fn get_hop_remaining_time(&self, edge_id: EdgeId) -> Option<u16> {
        if let Some(res) = self.hop_remaining_times.get(&edge_id) {
            return Some(*res);
        }
        None
    }

    pub fn get_nodes(&self) -> Vec<NodeId> {
        let mut nodes = Vec::new();
        let mut cur_id = self.source_id;
        for e in self.edges.clone() {
            nodes.push(cur_id);
            if let Some(neighbor_id) = e.borrow().neighbor_id(cur_id) {
                nodes.push(neighbor_id);
                cur_id = neighbor_id;
            }
        }

        let nodes: Vec<_> = nodes.into_iter().unique().collect();
        nodes
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let edges = self.edges.clone();
        write!(f, "[").unwrap();
        for e in edges {
            write!(f, " {} ", e.borrow()).unwrap();
        }
        write!(f, "]")
    }
}

fn read_most_central() -> Vec<NodeId> {
    let mut most_central_nodes = Vec::new();
    let file = File::open("most_central_nodes.csv").unwrap();
    for l in std::io::BufReader::new(file).lines() {
        most_central_nodes.push(l.unwrap().parse::<NodeId>().unwrap());
    }
    most_central_nodes
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_creation_works() {
        let data = r##"{
            "nodes": [
                {
                    "last_update": 1567764428,
                    "pub_key": "0200424bd89b5282c310e10a52fd783070556f947b54d93f73fd89534ce0cba708",
                    "alias": "test1",
                    "addresses": [
                        {
                            "network": "tcp",
                            "addr": "67.166.1.116:9735"
                        }
                    ],
                    "color": "#3399ff"
                },
                {
                    "last_update": 1567764428,
                    "pub_key": "0298f6074a454a1f5345cb2a7c6f9fce206cd0bf675d177cdbf0ca7508dd28852f",
                    "alias": "test2",
                    "addresses": [
                        {
                            "network": "tcp",
                            "addr": "67.166.1.116:9735"
                        }
                    ],
                    "color": "#3399ff"
                }
            ],
            "edges": [
                {
                    "channel_id": "659379322247708673",
                    "chan_point": "ae07c9fe78e6a1057902441f599246d735bac33be7b159667006757609fb5a86:1",
                    "last_update": 1571278793,
                    "node1_pub": "0200424bd89b5282c310e10a52fd783070556f947b54d93f73fd89534ce0cba708",
                    "node2_pub": "0298f6074a454a1f5345cb2a7c6f9fce206cd0bf675d177cdbf0ca7508dd28852f",
                    "capacity": "1000000",
                    "node1_policy": null,
                    "node2_policy": {
                        "time_lock_delta": 14,
                        "min_htlc": "1000",
                        "fee_base_msat": "1000",
                        "fee_rate_milli_msat": "1",
                        "disabled": false,
                        "max_htlc_msat": "990000000",
                        "last_update": 1571278793
                    }
                }
            ]
            }"##;
        let graph = Graph::from_json_str(&data.to_string());
        assert_eq!(graph.num_nodes(), 2);
        assert_eq!(graph.num_edges(), 1); 

        let node0_opt = graph.get_node(0);
        assert!(node0_opt.is_some());

        if let Some(node0) = node0_opt {
            assert_eq!(node0.borrow().neighbor_ids().len(), 1); 

            if let Some(node1) = graph.get_node(1) {
                assert!(node0.borrow().has_edge_to(1));
                assert!(node1.borrow().has_edge_to(0));
            }
        }
    }

    #[test]
    fn unknown_edges_are_discarded() {
        let data = r##"{
            "nodes": [
                {
                    "last_update": 1567764428,
                    "pub_key": "0200424bd89b5282c310e10a52fd783070556f947b54d93f73fd89534ce0cba708",
                    "alias": "test1",
                    "addresses": [
                        {
                            "network": "tcp",
                            "addr": "67.166.1.116:9735"
                        }
                    ],
                    "color": "#3399ff"
                },
                {
                    "last_update": 1567764428,
                    "pub_key": "0298f6074a454a1f5345cb2a7c6f9fce206cd0bf675d177cdbf0ca7508dd28852f",
                    "alias": "test2",
                    "addresses": [
                        {
                            "network": "tcp",
                            "addr": "67.166.1.116:9735"
                        }
                    ],
                    "color": "#3399ff"
                }
            ],
            "edges": [
                {
                    "channel_id": "659379322247708673",
                    "chan_point": "ae07c9fe78e6a1057902441f599246d735bac33be7b159667006757609fb5a86:1",
                    "last_update": 1571278793,
                    "node1_pub": "02899d09a65c5ca768c42b12e57d0497bfdf8ac1c46b0dcc0d4faefcdbc01304c1",
                    "node2_pub": "0298f6074a454a1f5345cb2a7c6f9fce206cd0bf675d177cdbf0ca7508dd28852f",
                    "capacity": "1000000",
                    "node1_policy": null,
                    "node2_policy": {
                        "time_lock_delta": 14,
                        "min_htlc": "1000",
                        "fee_base_msat": "1000",
                        "fee_rate_milli_msat": "1",
                        "disabled": false,
                        "max_htlc_msat": "990000000",
                        "last_update": 1571278793
                    }
                }
            ]
            }"##;
        let graph = Graph::from_json_str(&data.to_string());
        assert_eq!(graph.num_nodes(), 2);
        assert_eq!(graph.num_edges(), 0); // The edge above does not match to the node and is hence discarded
    }
}
