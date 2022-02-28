#![allow(dead_code)]
#[macro_use]
extern crate lazy_static;
mod config;
mod event;
mod simtime;
mod payment;
mod pathfind;
mod util;
mod graph;
mod geo;
mod latency;
mod adversary;

#[allow(unused_imports)] 
use log::{info,debug,trace};

use std::convert::TryInto;


use rand::SeedableRng;
use rand::rngs::SmallRng;

use std::rc::Rc;
use std::cell::RefCell;
use std::sync::{RwLock, Mutex};
use config::Config;
use event::{EventQueue, EventType};
use crate::simtime::SimTime;
use crate::graph::{Graph, NodeId, NodeRef, EdgeRef, PathRef, ChannelState};
use crate::payment::{Payment, MessageType, PaymentRef, PaymentId};
use crate::pathfind::PathFinder;
use crate::adversary::Adversary;

use std::fs::OpenOptions;

use std::fs::File; 
use std::io::prelude::*;


use std::time::{Instant};
use std::collections::{HashMap, BTreeMap};

lazy_static! {
    static ref CONFIG: RwLock<Config> = {
        let config = Config::new();
        RwLock::new(config)
    };
}

lazy_static! {
    static ref RNG: Mutex<SmallRng> = {
        let small_rng = SmallRng::from_entropy();
        Mutex::new(small_rng)
    };
}

pub struct Simulation {
    event_queue: EventQueue,
    graph: Graph,
    run: u64,
    amount: u64,
    num_tries: u32,
    adversary: String,
    num_malicious: u32,
    payments: HashMap<PaymentId, PaymentRef>,
    failed_payments: HashMap<PaymentId, PaymentRef>,
    successful_payments: HashMap<PaymentId, PaymentRef>,
    next_payment_id: PaymentId,
    tainted_paths: HashMap<PaymentId, PaymentRef>,
    observed_first_try_times: HashMap<PaymentId, SimTime>,
    observed_second_try_times: HashMap<PaymentId, SimTime>,
    observed_update_sent_times: HashMap<PaymentId, SimTime>,
    observed_fulfill_recvd_times: HashMap<PaymentId, SimTime>,
    estimated_sources_first_spy: HashMap<PaymentId, NodeRef>,
    estimated_destinations_first_spy: HashMap<PaymentId, NodeRef>,
    correct_sources_first_spy: HashMap<PaymentId, NodeRef>,
    correct_destinations_first_spy: HashMap<PaymentId, NodeRef>,
    estimated_sources_timing: HashMap<PaymentId, NodeRef>,
    estimated_destinations_timing: HashMap<PaymentId, NodeRef>,
    correct_sources_timing: HashMap<PaymentId, NodeRef>,
    correct_destinations_timing: HashMap<PaymentId, NodeRef>,
    malicious_dist_source: usize,
    malicious_dist_destination: usize,
}

impl Simulation {
    pub fn new(run: u64, amount: u64, num_tries: u32, adversary: String, num_malicious: u32) -> Option<Self> {
        {
            let mut rng = RNG.lock().unwrap();
            *rng = SmallRng::seed_from_u64(run); 
        }


        let payments = HashMap::new();
        let failed_payments = HashMap::new();
        let successful_payments = HashMap::new();
        let tainted_paths = HashMap::new();
        let observed_first_try_times = HashMap::new();
        let observed_second_try_times = HashMap::new();
        let observed_update_sent_times = HashMap::new();
        let observed_fulfill_recvd_times = HashMap::new();
        let estimated_sources_first_spy = HashMap::new();
        let estimated_destinations_first_spy = HashMap::new();
        let correct_sources_first_spy = HashMap::new();
        let correct_destinations_first_spy = HashMap::new();
        let estimated_sources_timing = HashMap::new();
        let estimated_destinations_timing = HashMap::new();
        let correct_sources_timing = HashMap::new();
        let correct_destinations_timing = HashMap::new();
        let next_payment_id = 0;

        match util::read_file(CONFIG.read().unwrap().lngraph_path()) { 
            Some(json_data) => {
                let event_queue = EventQueue::new();
                let graph = Graph::from_json_str(&json_data);
                let mut nodes_with_multi_edge = 0;
                let mut total_multi_edge_count = 0;
                for i in 0..graph.num_nodes() {
                    let n = graph.get_node_ref(i.try_into().unwrap()).unwrap();
                    let neighbors = n.borrow().neighbor_ids();
                    for neighbor in neighbors {
                        let num_edges = n.borrow().edges_to_neighbor(neighbor).len();
                        if num_edges > 1 {
                            nodes_with_multi_edge += 1;
                            total_multi_edge_count += num_edges;
                        }
                    }
                }

                let malicious_dist_source = 0;
                let malicious_dist_destination = 0;
                info!("num_nodes: {}, num_edges: {}", graph.num_nodes(), graph.num_edges());
                info!("nodes_with_multi_edge: {}, total_multi_edge_count: {}", nodes_with_multi_edge, total_multi_edge_count);

                Some(Self { 
                    event_queue,
                    graph,
                    run,
                    amount,
                    num_tries,
                    adversary,
                    num_malicious,
                    payments,
                    successful_payments,
                    failed_payments,
                    tainted_paths,
                    observed_first_try_times,
                    observed_second_try_times,
                    observed_update_sent_times,
                    observed_fulfill_recvd_times,
                    estimated_sources_first_spy,
                    estimated_destinations_first_spy,
                    correct_sources_first_spy,
                    correct_destinations_first_spy,
                    estimated_sources_timing,
                    estimated_destinations_timing,
                    correct_sources_timing,
                    correct_destinations_timing,
                    next_payment_id,
                    malicious_dist_source,
                    malicious_dist_destination,
                })
            },
            None => None,
        }
    }

    pub fn run(&mut self) {
        let most_central_nodes = self.graph.get_m_most_central_nodes(self.num_malicious).clone();
        let random_nodes = self.graph.get_m_random_nodes(self.num_malicious).clone();
        let lnbig_nodes = self.graph.get_lnbig_nodes();

        let mut malicious_nodes_iter = if self.adversary == "mcentral" {
            most_central_nodes.iter()
        } else if self.adversary == "mrandom" {
            random_nodes.iter()
        } else {
            self.num_malicious = lnbig_nodes.len() as u32;
            lnbig_nodes.iter()
        };

        while let Some(adv_node_id) = malicious_nodes_iter.next() {
            let adv_node_ref = self.graph.get_node_ref(*adv_node_id).unwrap();
            adv_node_ref.borrow_mut().set_malicious();
        }

        let mut cur_time = SimTime::from_secs(0.0);
        for _ in 0..self.num_tries {
            let source = self.graph.get_random_node().unwrap();
            let destination = self.graph.get_random_node().unwrap();

            //info!("Rand: {} {}", source.borrow().node_id(), destination.borrow().node_id());
            let event = EventType::ScheduledPayment { source: Rc::clone(&source), destination: Rc::clone(&destination), amount: self.amount };
            self.event_queue.schedule(cur_time, event);
            cur_time += SimTime::from_secs(120.0);
        }

        while let Some(next_event) = self.event_queue.next() {
            match next_event {
                EventType::MessageReceived{ sender, receiver, edge, message } => {
                    debug!{"Received now {}: Node {} received message: {:?}", self.event_queue.now(), receiver.borrow().node_id(), message};
                    self.handle_message(Rc::clone(&sender), Rc::clone(&receiver), Rc::clone(&edge), message);
                },
                EventType::ScheduledPayment{ source, destination, amount } => {
                    self.send_payment(Rc::clone(&source), Rc::clone(&destination), amount, None);
                }
            }
        }


        let num_payments: f32 = self.payments.len() as f32;
        let num_successful: f32 = self.successful_payments.len() as f32;
        let num_observed_source: f32 = self.observed_second_try_times.len() as f32;
        let num_observed_destination: f32 = self.observed_fulfill_recvd_times.len() as f32;
        let num_tainted = self.tainted_paths.len() as f32;
        let success_rate = num_successful/num_payments;
        let tainted_rate = num_tainted/num_payments;

        let mut num_total_denon_first_spy = 0;
        for key in self.correct_sources_first_spy.keys() {
            if self.correct_destinations_first_spy.contains_key(key) {
                num_total_denon_first_spy += 1;
            }
        }

        let mut num_total_denon_timing = 0;
        for key in self.correct_sources_timing.keys() {
            if self.correct_destinations_timing.contains_key(key) {
                num_total_denon_timing += 1;
            }
        }

        let mut path_len_sum = 0;
        for (_,p) in self.payments.clone() {
            let len = p.borrow().path().borrow().len();
            path_len_sum += len;
        }
        let avg_path_length: f32 = path_len_sum as f32 / num_payments;

        let mut tainted_len_sum = 0;
        for (_,p) in self.tainted_paths.clone() {
            let len = p.borrow().path().borrow().len();
            tainted_len_sum += len;
        }
        let avg_tainted_path_length: f32 = tainted_len_sum as f32 / num_tainted;

        let mut timelocks: Vec<f32> = Vec::new();
        for (_,p) in self.payments.clone() {
            let necessary_time_lock = p.borrow().max_time_lock;
            timelocks.push(necessary_time_lock as f32);
        }
        timelocks.sort_by(|a,b| a.partial_cmp(b).unwrap());
        let mid = timelocks.len() / 2;
        let median_timelock: f32 = timelocks[mid];
        let avg_timelock: f32 = timelocks.iter().sum::<f32>()/(timelocks.len() as f32);

        let num_source_true_pos_first_spy: f32 = self.correct_sources_first_spy.len() as f32;
        let num_source_true_pos_timing: f32 = self.correct_sources_timing.len() as f32;
        let num_destination_true_pos_first_spy: f32 = self.correct_destinations_first_spy.len() as f32;
        let num_destination_true_pos_timing: f32 = self.correct_destinations_timing.len() as f32;

        let source_precision_first_spy = num_source_true_pos_first_spy / num_observed_source;
        let source_precision_timing = num_source_true_pos_timing / num_observed_source;
        let destination_precision_first_spy = num_destination_true_pos_first_spy / num_observed_destination;
        let destination_precision_timing = num_destination_true_pos_timing / num_observed_destination;
        let total_deanon_precision_first_spy = num_total_denon_first_spy as f32 / num_observed_source;
        let total_deanon_precision_timing = num_total_denon_timing as f32 / num_observed_source;

        let source_recall_first_spy = num_source_true_pos_first_spy / num_payments;
        let source_recall_timing = num_source_true_pos_timing / num_payments;
        let destination_recall_first_spy = num_destination_true_pos_first_spy / num_payments;
        let destination_recall_timing = num_destination_true_pos_timing / num_payments;
        let total_deanon_recall_first_spy = num_total_denon_first_spy as f32 / num_payments;
        let total_deanon_recall_timing = num_total_denon_timing as f32 / num_payments;

        let source_f_first_spy = 2.0 * (source_precision_first_spy * source_recall_first_spy) / (source_precision_first_spy + source_recall_first_spy);
        let source_f_timing = 2.0 * (source_precision_timing * source_recall_timing) / (source_precision_timing + source_recall_timing);

        let destination_f_first_spy = 2.0 * (destination_precision_first_spy * destination_recall_first_spy) / (destination_precision_first_spy + destination_recall_first_spy);
        let destination_f_timing = 2.0 * (destination_precision_timing * destination_recall_timing) / (destination_precision_timing + destination_recall_timing);

        let total_deanon_f_first_spy = 2.0 * (total_deanon_precision_first_spy * total_deanon_recall_first_spy) / (total_deanon_precision_first_spy + total_deanon_recall_first_spy);
        let total_deanon_f_timing = 2.0 * (total_deanon_precision_timing * total_deanon_recall_timing) / (total_deanon_precision_timing + total_deanon_recall_timing);

        let avg_malicious_dist_source = self.malicious_dist_source as f32 / num_tainted;
        let avg_malicious_dist_destination = self.malicious_dist_destination as f32 / num_tainted;
        info!("Simulated {} payments, {} succeeded, {} failed.", num_payments, num_successful, num_payments-num_successful);
        info!("Success rate: {}", success_rate);

        info!("Tainted payment paths: {}, tainted rate: {}, tainted len: {}", num_tainted, tainted_rate, avg_tainted_path_length);
        info!("Avg. length: {}, malicious dist source: {}, destination: {}", avg_path_length, avg_malicious_dist_source, avg_malicious_dist_destination);
        info!("Avg. timelock: {}, Median timelock: {}", avg_timelock, median_timelock);
        //info!("Total malicious dist source: {}, destination: {}", self.malicious_dist_source, self.malicious_dist_destination);

        info!("Correct source estimations First-Spy: {}, precision: {}, recall: {}, F: {}", num_source_true_pos_first_spy, source_precision_first_spy, source_recall_first_spy, source_f_first_spy);
        info!("Correct destination estimations First-Spy: {}, precision: {}, recall: {}, F: {}", num_destination_true_pos_first_spy, destination_precision_first_spy, destination_recall_first_spy, destination_f_first_spy);
        info!("Correct total payment estimations First-Spy: {}, precision: {}, recall: {}, F: {}", num_total_denon_first_spy, total_deanon_precision_first_spy, total_deanon_recall_first_spy, total_deanon_f_first_spy);

        info!("Correct source estimations Timing: {}, precision: {}, recall: {}, F: {}", num_source_true_pos_timing, source_precision_timing, source_recall_timing, source_f_timing);
        info!("Correct destination estimations Timing: {}, precision: {}, recall: {}, F: {}", num_destination_true_pos_timing, destination_precision_timing, destination_recall_timing, destination_f_timing);
        info!("Correct total payment estimations Timing: {}, precision: {}, recall: {}, F: {}", num_total_denon_timing, total_deanon_precision_timing, total_deanon_recall_timing, total_deanon_f_timing);


        let header_str = "run,amount,adversary,num_malicious,num_tries,num_payments,avg_path_length,avg_tainted_path_length,avg_malicious_dist_source,avg_malicious_dist_destination,num_tainted,tainted_rate,num_successful,success_rate,num_source_true_pos_first_spy,num_source_true_pos_timing,num_destination_true_pos_first_spy,num_destination_true_pos_timing,source_precision_first_spy,source_precision_timing,destination_precision_first_spy,destination_precision_timing,total_deanon_precision_first_spy,total_deanon_precision_timing,source_recall_first_spy,source_recall_timing,destination_recall_first_spy,destination_recall_timing,total_deanon_recall_first_spy,total_deanon_recall_timing,source_f_first_spy,source_f_timing,destination_f_first_spy,destination_f_timing,total_deanon_f_first_spy,total_deanon_f_timing";

        let out_filename = "cdtsim_results.csv";

        let mut created_file = false;


        let mut file = if let Ok(file_opened) = OpenOptions::new().append(true).open(out_filename) {
            file_opened
        } else if let Ok(file_created) = OpenOptions::new().create_new(true).append(true).open(out_filename) {
            created_file = true;
            file_created
        } else {
            return;
        };

        if created_file {
            let _ = write!{file, "{}\n", header_str};
        }

        let _ = write!{file, "{},", self.run};
        let _ = write!{file, "{},", self.amount};
        let _ = write!{file, "{},", self.adversary};
        let _ = write!{file, "{},", self.num_malicious};
        let _ = write!{file, "{},", self.num_tries};
        let _ = write!{file, "{},", num_payments};
        let _ = write!{file, "{},", avg_path_length};
        let _ = write!{file, "{},", avg_tainted_path_length};
        let _ = write!{file, "{},", avg_malicious_dist_source};
        let _ = write!{file, "{},", avg_malicious_dist_destination};
        let _ = write!{file, "{},", num_tainted};
        let _ = write!{file, "{},", tainted_rate};
        let _ = write!{file, "{},", num_successful};
        let _ = write!{file, "{},", success_rate};
        let _ = write!{file, "{},", num_source_true_pos_first_spy};
        let _ = write!{file, "{},", num_source_true_pos_timing};
        let _ = write!{file, "{},", num_destination_true_pos_first_spy};
        let _ = write!{file, "{},", num_destination_true_pos_timing};
        let _ = write!{file, "{},", source_precision_first_spy};
        let _ = write!{file, "{},", source_precision_timing};
        let _ = write!{file, "{},", destination_precision_first_spy};
        let _ = write!{file, "{},", destination_precision_timing};
        let _ = write!{file, "{},", total_deanon_precision_first_spy};
        let _ = write!{file, "{},", total_deanon_precision_timing};
        let _ = write!{file, "{},", source_recall_first_spy};
        let _ = write!{file, "{},", source_recall_timing};
        let _ = write!{file, "{},", destination_recall_first_spy};
        let _ = write!{file, "{},", destination_recall_timing};
        let _ = write!{file, "{},", total_deanon_recall_first_spy};
        let _ = write!{file, "{},", total_deanon_recall_timing};
        let _ = write!{file, "{},", source_f_first_spy};
        let _ = write!{file, "{},", source_f_timing};
        let _ = write!{file, "{},", destination_f_first_spy};
        let _ = write!{file, "{},", destination_f_timing};
        let _ = write!{file, "{},", total_deanon_f_first_spy};
        let _ = write!{file, "{}", total_deanon_f_timing};
        let _ = write!{file, "\n"};
    }

    fn send_payment(&mut self, source: NodeRef, destination: NodeRef, amount: u64, retry_of: Option<PaymentId>) {
        let source_id = source.borrow().node_id();
        let destination_id = destination.borrow().node_id();
        let max_time_lock = CONFIG.read().unwrap().default_max_time_lock();

        let start_time = Instant::now();
        let mut finder = PathFinder::new(source_id, destination_id, amount, max_time_lock, Box::new(self.graph.clone()));
        if let Some((path, total_amount_to_send, necessary_time_lock)) = finder.find_path() {
            let duration = start_time.elapsed();
            let nodes = path.get_nodes();
            info!("Path found after {} ms. Path len: {}, total_amount_to_send: {}, necessary_time_lock: {}, path: {}, nodes: {:?}", duration.as_millis(), path.len(), total_amount_to_send, necessary_time_lock, path, nodes);
            let path_ref = Rc::new(RefCell::new(path.clone()));
            let first_malicious_node = self.get_first_malicious_node(Rc::clone(&path_ref));
            let last_malicious_node = self.get_last_malicious_node(Rc::clone(&path_ref));
            let payment_id = self.next_payment_id();
            let payment_ref = Rc::new(RefCell::new(Payment::new(payment_id, 
                                                                retry_of, 
                                                                Rc::clone(&source),
                                                                Rc::clone(&destination),
                                                                amount,
                                                                necessary_time_lock,
                                                                Rc::clone(&path_ref),
                                                                first_malicious_node.clone(),
                                                                last_malicious_node.clone(),
                                                                )));
            if source == destination {
                self.successful_payments.insert(payment_id, Rc::clone(&payment_ref));
                return;
            }
            if first_malicious_node.is_some() {
                info!("Path nodes: {:?}, first_malicious_node: {}, last_malicious_node: {}", nodes, first_malicious_node.clone().unwrap().borrow().node_id(), last_malicious_node.clone().unwrap().borrow().node_id());
                if retry_of.is_none() {
                    self.tainted_paths.insert(payment_id, Rc::clone(&payment_ref));
                    let first_malicious_dist = self.get_first_malicious_node_pos(Rc::clone(&path_ref)).unwrap();
                    self.malicious_dist_source += first_malicious_dist;
                    info!("first malicious dist: {}, path len: {}", first_malicious_dist, path.len());
                }
            }
            if last_malicious_node.is_some() {
                if retry_of.is_none() {
                    self.tainted_paths.insert(payment_id, Rc::clone(&payment_ref));
                    let last_malicious_dist = path_ref.borrow().len()-self.get_last_malicious_node_pos(Rc::clone(&path_ref)).unwrap();
                    self.malicious_dist_destination += last_malicious_dist;
                    info!("last malicious dist: {}, path len: {}", last_malicious_dist, path.len());
                }
            }

            if retry_of.is_none() {
                self.payments.insert(payment_id, Rc::clone(&payment_ref));
                if source.borrow().is_malicious() {
                    self.correct_sources_first_spy.insert(payment_id, Rc::clone(&source));
                    self.correct_sources_timing.insert(payment_id, Rc::clone(&source));
                }
                if destination.borrow().is_malicious() {
                    self.correct_destinations_first_spy.insert(payment_id, Rc::clone(&destination));
                    self.correct_destinations_timing.insert(payment_id, Rc::clone(&destination));
                }
            }
            self.forward_payment(Rc::clone(&payment_ref));
        }
    }

    fn retry_payment(&mut self, payment_ref: PaymentRef) {
        let cur_node_ref = payment_ref.borrow().get_current_hop();
        let cur_id = cur_node_ref.borrow().node_id();
        let payment_id = payment_ref.borrow().payment_id();
        info!("{} | N {}: Retrying payment {}!", self.event_queue.now(), cur_id, payment_id);

        let source = payment_ref.borrow().source();
        let destination = payment_ref.borrow().destination();
        let amount = payment_ref.borrow().amount().clone();
        let payment_id = payment_ref.borrow().payment_id().clone();
        self.send_payment(Rc::clone(&source), Rc::clone(&destination), amount, Some(payment_id));
    }

    fn queue_message(&mut self, sender: NodeRef, receiver: NodeRef, edge: EdgeRef, message: MessageType) {
        let m = vec!{message};
        self.queue_messages(sender, receiver, edge, m);
    }

    fn queue_messages(&mut self, sender: NodeRef, receiver: NodeRef, edge: EdgeRef, messages: Vec<MessageType>) {
        let mut sampled_delays = Vec::new();
        for _ in 0..messages.len() {
            let sampled_delay = SimTime::from_millis(edge.borrow_mut().latency_dist().sample());
            sampled_delays.push(sampled_delay);
        }
        sampled_delays.sort();
        sampled_delays.reverse();

        for msg in messages {
            let delay = sampled_delays.pop().unwrap();
            let event = EventType::MessageReceived {sender: Rc::clone(&sender), receiver: Rc::clone(&receiver), edge: Rc::clone(&edge), message: msg}; 
            self.event_queue.schedule(delay, event);
        }
    }

    fn handle_message(&mut self, sender_ref: NodeRef, receiver_ref: NodeRef, edge_ref: EdgeRef, message: MessageType) {
        let sender_id = sender_ref.borrow().node_id();
        let receiver_id = receiver_ref.borrow().node_id();
        assert_eq!(edge_ref.borrow().neighbor_id(sender_id).unwrap(), receiver_id);
        assert_eq!(edge_ref.borrow().neighbor_id(receiver_id).unwrap(), sender_id);
        // FIXME: While we are considering the case that multiple state updates can occur at the
        // same time, we currently resolve this by always opting for the newest state and
        // discarding all others. In our case, this should have no impact because we choose
        // payment intervals high enough so that in most cases there is only one HTLC negotiated at
        // any point in time. However, for lower intervals the current behavior is not entirely
        // correct and may lead to inaccurate results.
        match message {
            MessageType::UpdateAddHtlc { amount, remaining_time, payment_ref } => {
                // update current node/path context
                payment_ref.borrow_mut().set_current_hop(Rc::clone(&receiver_ref));
                payment_ref.borrow().path().borrow_mut().walk_forward();

                let cur_node_ref = payment_ref.borrow().get_current_hop();
                let cur_id = cur_node_ref.borrow().node_id();
                let cur_time = self.event_queue.now();
                let payment_id = payment_ref.borrow().payment_id();
                info!("{} | N {}: Received payment {} with amount: {}, remaining_time: {}", self.event_queue.now(), cur_id, payment_id, amount, remaining_time);

                let p_id = if let Some(old_payment_id) = payment_ref.borrow().retry_of() {
                    old_payment_id
                } else {
                    payment_id
                };

                if payment_ref.borrow().is_first_malicious_node(Rc::clone(&cur_node_ref)) && payment_ref.borrow().is_retry() {
                    if let Some(first_try_time) = self.observed_first_try_times.get(&p_id) {
                        if self.observed_second_try_times.contains_key(&p_id) {
                            return;
                        }
                            
                        self.observed_second_try_times.insert(p_id, cur_time);

                        let cur_edge_id = edge_ref.borrow().edge_id();
                        let prev_forwarded_amount = payment_ref.borrow().path().borrow().get_hop_amount_to_forward(cur_edge_id).unwrap();
                        let prev_remaining_time = payment_ref.borrow().path().borrow().get_hop_remaining_time(cur_edge_id).unwrap();

                        // we already saw this payment before
                        info!("{} | N {}: First malicious node observed payment {} (now: {}) a second time. Time difference: {}", self.event_queue.now(), cur_id, p_id, payment_id, cur_time - *first_try_time);
                        let mut adv = Adversary::new(Rc::clone(&cur_node_ref), Rc::clone(&edge_ref), prev_forwarded_amount, prev_remaining_time, Box::new(self.graph.clone()));

                        let first_spy_source = adv.first_spy_estimate_source();
                        self.estimated_sources_first_spy.insert(p_id, Rc::clone(&first_spy_source));
                        if payment_ref.borrow().source() == first_spy_source {
                            info!("{} | N {}: First malicious node correct source estimation for payment {}", self.event_queue.now(), cur_id, p_id);
                            self.correct_sources_first_spy.insert(p_id, first_spy_source);
                        }

                        let time_diff = cur_time-*first_try_time;

                        let timing_source = adv.timing_estimate_source(time_diff.as_millis() as f64); 
                        self.estimated_sources_timing.insert(p_id, Rc::clone(&timing_source));
                        if payment_ref.borrow().source() == timing_source {
                            info!("{} | N {}: First malicious node correct timing source estimation for payment {}", self.event_queue.now(), cur_id, p_id);
                            self.correct_sources_timing.insert(p_id, timing_source);
                        } else {
                            info!("{} | N {}: First malicious estimated destionation: {}", self.event_queue.now(), cur_id, timing_source.borrow().node_id());
                        }
                    }
                }


                // ... waiting for state change ...


            },
            MessageType::UpdateFailHtlc { payment_ref } => {
                // update current node/path context
                payment_ref.borrow_mut().set_current_hop(Rc::clone(&receiver_ref));
                payment_ref.borrow().path().borrow_mut().walk_backward();

                let cur_node_ref = payment_ref.borrow().get_current_hop();
                let cur_id = cur_node_ref.borrow().node_id();
                if cur_node_ref == payment_ref.borrow().source() {
                    if !payment_ref.borrow().is_retry() {
                        //// Lets retry failed payments
                        //info!("{} | N {}: Retrying payment {}!", self.event_queue.now(), cur_id, payment_ref.borrow().payment_id());

                        //let source = payment_ref.borrow().source();
                        //let destination = payment_ref.borrow().destination();
                        //let amount = payment_ref.borrow().amount().clone();
                        //let payment_id = payment_ref.borrow().payment_id().clone();
                        //self.send_payment(Rc::clone(&source), Rc::clone(&destination), amount, Some(payment_id));
                    } else {
                        info!("{} | N {}: Payment {} finally failed!", self.event_queue.now(), cur_id, payment_ref.borrow().payment_id());
                        self.failed_payments.insert(payment_ref.borrow().payment_id(), Rc::clone(&payment_ref));
                    }

                } else {
                    self.fail_payment(Rc::clone(&payment_ref));
                }
            },
            MessageType::UpdateFulfillHtlc { payment_ref } => {
                // update current node/path context
                payment_ref.borrow_mut().set_current_hop(Rc::clone(&receiver_ref));
                payment_ref.borrow().path().borrow_mut().walk_backward();

                let cur_node_ref = payment_ref.borrow().get_current_hop();
                let cur_id = cur_node_ref.borrow().node_id();
                let payment_id = payment_ref.borrow().payment_id();

                if payment_ref.borrow().is_last_malicious_node(Rc::clone(&receiver_ref)) {
                    // we are the first malicious node
                    let cur_time = self.event_queue.now();
                    let p_id = if let Some(old_payment_id) = payment_ref.borrow().retry_of() {
                        old_payment_id
                    } else {
                        payment_id
                    };
                    self.observed_fulfill_recvd_times.insert(p_id, cur_time);

                    if let Some(first_time) = self.observed_update_sent_times.get(&p_id) {
                        // we already saw this payment before
                        let time_diff = cur_time-*first_time;
                        info!("{} | N {}: Last malicious node observed payment {} a second time. Time difference: {}", self.event_queue.now(), cur_id, p_id, cur_time-*first_time);

                        let cur_edge_id = edge_ref.borrow().edge_id();
                        let forwarded_amount = payment_ref.borrow().path().borrow().get_hop_amount_to_forward(cur_edge_id).unwrap();
                        let remaining_time = payment_ref.borrow().path().borrow().get_hop_remaining_time(cur_edge_id).unwrap();
                        assert_eq!(cur_node_ref, receiver_ref);
                        assert_eq!(edge_ref.borrow().neighbor_id(sender_id).unwrap(), receiver_id);
                        assert_eq!(edge_ref.borrow().neighbor_id(receiver_id).unwrap(), sender_id);
                        info!("receiver_id: {}, edge: {}", receiver_id, edge_ref.borrow());

                        let mut adv = Adversary::new(Rc::clone(&receiver_ref), Rc::clone(&edge_ref), forwarded_amount, remaining_time, Box::new(self.graph.clone()));

                        let first_spy_destination = adv.first_spy_estimate_destination(); 
                        self.estimated_destinations_first_spy.insert(p_id, Rc::clone(&first_spy_destination));
                        if payment_ref.borrow().destination() == first_spy_destination {
                            info!("{} | N {}: Last malicious node correct destination estimation for payment {}", self.event_queue.now(), cur_id, p_id);
                            self.correct_destinations_first_spy.insert(p_id, first_spy_destination);
                        }

                        let timing_destination = adv.timing_estimate_destination(time_diff.as_millis() as f64); 
                        self.estimated_destinations_timing.insert(p_id, Rc::clone(&timing_destination));
                        if payment_ref.borrow().destination() == timing_destination {
                            info!("{} | N {}: Last malicious node correct timing destination estimation for payment {}", self.event_queue.now(), cur_id, p_id);
                            self.correct_destinations_timing.insert(p_id, timing_destination);
                        } else {
                            info!("{} | N {}: Last malicious estimated destination: {}", self.event_queue.now(), cur_id, timing_destination.borrow().node_id());
                        }

                        // if our next node was the destination, print the measured time vs the expectation
                        let expectation = crate::adversary::estimate_latency_distribution(Rc::clone(&edge_ref));
                        let expectation_four = crate::adversary::estimate_latency_distribution(Rc::clone(&edge_ref)) * 4.0 as f64;
                        if sender_ref == payment_ref.borrow().destination() {
                            info!("{} | N {}: Measured: {}, Expectation: {}, Four times expectation: {}", self.event_queue.now(), cur_id, time_diff.as_millis(), expectation.mean(), expectation_four.mean());
                        }
                    } else {
                        info!("{} | N {}: Last malicious node observed payment {} a second time. BUT NO PRIOR MEASUREMENT?!?", self.event_queue.now(), cur_id, payment_id);
                        //info!("{:?}", self.observed_update_sent_times);
                    }
                }
                if cur_node_ref == payment_ref.borrow().source() {
                    info!("{} | N {}: Payment {} finally succeeded!", self.event_queue.now(), cur_id, payment_id);
                    self.successful_payments.insert(payment_ref.borrow().payment_id(), Rc::clone(&payment_ref));
                } else {
                    self.fulfill_payment(Rc::clone(&payment_ref));
                }
            },
            MessageType::CommitmentSigned { state_ref, payment_ref } => {
                //info!("{} | N {}: Payment {} Committed.", self.event_queue.now(), receiver.borrow().node_id(), payment_ref.borrow().payment_id());
                if !edge_ref.borrow().update_is_valid(Rc::clone(&state_ref)) { return; }
                state_ref.borrow_mut().set_state_committed(Rc::clone(&sender_ref));

                let mut reply_messages = Vec::new();

                if !state_ref.borrow().state_is_acked(Rc::clone(&receiver_ref)) {
                    let reply_revoke = MessageType::RevokeAndAck { state_ref: Rc::clone(&state_ref), payment_ref: Rc::clone(&payment_ref) };
                    reply_messages.push(reply_revoke);
                }

                if !state_ref.borrow().state_is_committed(Rc::clone(&receiver_ref)) {
                    let reply_commit = MessageType::CommitmentSigned { state_ref: Rc::clone(&state_ref), payment_ref: Rc::clone(&payment_ref) };
                    reply_messages.push(reply_commit);
                }
                self.queue_messages(Rc::clone(&receiver_ref), Rc::clone(&sender_ref), Rc::clone(&edge_ref), reply_messages);
            },
            MessageType::RevokeAndAck { state_ref, payment_ref } => {
                //info!("{} | N {}: Payment {} revoked.", self.event_queue.now(), receiver.borrow().node_id(), payment_ref.borrow().payment_id());
                if !edge_ref.borrow().update_is_valid(Rc::clone(&state_ref)) { return; }
                state_ref.borrow_mut().set_state_acked(Rc::clone(&sender_ref));

                // check if state negotiation is done
                let committed_sender = state_ref.borrow().state_is_committed(Rc::clone(&sender_ref));
                let committed_receiver = state_ref.borrow().state_is_committed(Rc::clone(&sender_ref));
                let acked_sender = state_ref.borrow().state_is_acked(Rc::clone(&sender_ref));
                let acked_receiver = state_ref.borrow().state_is_acked(Rc::clone(&sender_ref));
                if committed_sender && committed_receiver && acked_sender && acked_receiver {
                    info!("{} | N {}: Payment {} committed and revoked. Updating channel state: {}", self.event_queue.now(), receiver_ref.borrow().node_id(), payment_ref.borrow().payment_id(), state_ref.borrow().state_id());
                    // if so, update the 'official' state
                    edge_ref.borrow_mut().update_channel_state(Rc::clone(&state_ref));
                    // we thereby invaldiated the update
                    assert!(!edge_ref.borrow().update_is_valid(Rc::clone(&state_ref)));

                    //println!("Sender id: {}, Receiver id: {}", sender.borrow().node_id(), receiver.borrow().node_id());
                    let cur_node_ref = payment_ref.borrow().get_current_hop();
                    let cur_id = cur_node_ref.borrow().node_id();
                    let cur_payment_id = payment_ref.borrow().payment_id();
                    let p_id = if let Some(old_payment_id) = payment_ref.borrow().retry_of() {
                        old_payment_id
                    } else {
                        cur_payment_id
                    };

                    if cur_node_ref == payment_ref.borrow().source() {
                        // source should retry failed payments once
                        if payment_ref.borrow().has_failed() && !payment_ref.borrow().is_retry() {
                            self.retry_payment(Rc::clone(&payment_ref));
                            return;
                        }
                    } 

                    if cur_node_ref == payment_ref.borrow().destination() {
                        // destination should fulfill payment, but fail first tries
                        if payment_ref.borrow().is_first_malicious_node(Rc::clone(&cur_node_ref)) {
                            let cur_time = self.event_queue.now();
                            if !payment_ref.borrow().is_retry() {
                                // this is no retry, fail first observed payment
                                self.observed_first_try_times.insert(p_id, cur_time);
                                info!("{} | N {}: First malicious node observed payment {} a first time.", self.event_queue.now(), cur_id, p_id);
                                payment_ref.borrow_mut().set_failed();
                                self.fail_payment(Rc::clone(&payment_ref));
                                return;
                            }
                        } 
                        self.fulfill_payment(Rc::clone(&payment_ref));
                        return;
                    } 

                    if payment_ref.borrow().has_failed() {
                        // if the payment has already failed, we're on the reverse path and hence
                        // done
                        return;
                    }

                    // intermediate nodes should forward and/or act malicious
                    //println!("Sender id: {}, Receiver id: {}", sender.borrow().node_id(), receiver.borrow().node_id());
                    if payment_ref.borrow().is_first_malicious_node(Rc::clone(&cur_node_ref)) {
                        let cur_time = self.event_queue.now();
                        if !payment_ref.borrow().is_retry() {
                            // this is no retry, fail first observed payment
                            self.observed_first_try_times.insert(p_id, cur_time);
                            info!("{} | N {}: First malicious node observed payment {} a first time.", self.event_queue.now(), cur_id, p_id);
                            payment_ref.borrow().path().borrow_mut().walk_backward();
                            payment_ref.borrow_mut().set_failed();
                            self.fail_payment(Rc::clone(&payment_ref));
                            return;
                        }
                    }

                    // try normal forwarding
                    if !self.forward_payment(Rc::clone(&payment_ref)) {
                        payment_ref.borrow_mut().set_failed();
                        payment_ref.borrow().path().borrow_mut().walk_backward();
                        self.fail_payment(Rc::clone(&payment_ref));
                    }
                }
            },
            _ => {},
        }
    }

    fn fail_payment(&mut self, payment_ref: PaymentRef) {
        let cur_node_ref = payment_ref.borrow().get_current_hop();
        let cur_id = cur_node_ref.borrow().node_id();
        info!("{} | N {}: Failing payment {}.", self.event_queue.now(), cur_id, payment_ref.borrow().payment_id());
        let mut reply_messages = Vec::new();
        if let Some(prev_edge_ref) = payment_ref.borrow().path().borrow().cur_edge() {
            //info!("{} | N {}: fail_payment: {}.", self.event_queue.now(), cur_id, prev_edge_ref.borrow());
            let prev_id = prev_edge_ref.borrow().neighbor_id(cur_id).unwrap();
            let prev_node_ref = self.graph.get_node_ref(prev_id).unwrap();

            //info!{"{}: Payment {} prev hop: {}", self.event_queue.now(), payment_ref.borrow().payment_id(), prev_id};
            let fail_message = MessageType::UpdateFailHtlc{ payment_ref: Rc::clone(&payment_ref) };
            reply_messages.push(fail_message);

            let prev_edge_id = prev_edge_ref.borrow().edge_id();
            let forwarded_amount = payment_ref.borrow().path().borrow().get_hop_amount_to_forward(prev_edge_id).unwrap();
            let old_state_ref = prev_edge_ref.borrow().channel_state();

            let old_state_id = old_state_ref.borrow().state_id();
            let old_node1_id = old_state_ref.borrow().node1_id();
            let old_node2_id = old_state_ref.borrow().node2_id();
            let old_node1_balance = old_state_ref.borrow().node1_balance();
            let old_node2_balance = old_state_ref.borrow().node2_balance();

            //info!{"old_node1_balance: {}, old_node2_balance: {}, amount_to_forward: {}", old_node1_balance, old_node2_balance, amount_to_forward}

            let new_node1_balance = if cur_id == old_node1_id {
                old_node1_balance+forwarded_amount
            } else {
                old_node1_balance-forwarded_amount
            };

            let new_node2_balance = if cur_id == old_node2_id {
                old_node2_balance+forwarded_amount
            } else {
                old_node2_balance-forwarded_amount
            };
            let capacity = prev_edge_ref.borrow().capacity();
            assert_eq!(capacity, old_node1_balance+old_node2_balance);
            assert_eq!(capacity, new_node1_balance+new_node2_balance);
            //info!{"new_node1_balance: {}, new_node2_balance: {}, amount_to_forward: {}", new_node1_balance, new_node2_balance, amount_to_forward}

            let new_state_id = old_state_id + 1;
            let new_state_ref = Rc::new(RefCell::new(ChannelState::new(
                        new_state_id,
                        old_node1_id,
                        old_node2_id,
                        new_node1_balance,
                        new_node2_balance
                        )));

            let commit_message = MessageType::CommitmentSigned { state_ref: new_state_ref, payment_ref: Rc::clone(&payment_ref) };
            reply_messages.push(commit_message);

            self.queue_messages(Rc::clone(&cur_node_ref), Rc::clone(&prev_node_ref), Rc::clone(&prev_edge_ref), reply_messages);
        } 
    }

    fn fulfill_payment(&mut self, payment_ref: PaymentRef) {
        let cur_node_ref = payment_ref.borrow().get_current_hop();
        let cur_id = cur_node_ref.borrow().node_id();
        info!("{} | N {}: Fulfilling payment {}.", self.event_queue.now(), cur_id, payment_ref.borrow().payment_id());
        if let Some(prev_edge_ref) = payment_ref.borrow().path().borrow().cur_edge() {

            //info!("{} | N {}: fulfill_payment: {}.", self.event_queue.now(), cur_id, prev_edge_ref.borrow());
            let prev_id = prev_edge_ref.borrow().neighbor_id(cur_id).unwrap();
            let prev_node_ref = self.graph.get_node_ref(prev_id).unwrap();

            //info!{"{}: Payment {} prev hop: {}", self.event_queue.now(), payment_ref.borrow().payment_id(), prev_id};

            let message = MessageType::UpdateFulfillHtlc{ payment_ref: Rc::clone(&payment_ref) };
            self.queue_message(cur_node_ref, prev_node_ref, prev_edge_ref, message);
        } 
    }

    fn forward_payment(&mut self, payment_ref: PaymentRef) -> bool {
        let cur_node_ref = payment_ref.borrow().get_current_hop();
        let cur_id = cur_node_ref.borrow().node_id();
        info!("{} | N {}: Forwarding payment {}.", self.event_queue.now(), cur_id, payment_ref.borrow().payment_id());
        // get next edge (and thereby advance the path's current hop)
        if let Some(cur_edge_ref) = payment_ref.borrow().path().borrow().cur_edge() {
            //info!("{} | N {}: forward_payment: {}.", self.event_queue.now(), cur_id, cur_edge_ref.borrow());
            let cur_edge_id = cur_edge_ref.borrow().edge_id();

            //println!("Next edge: {:?}",next_edge_ref);
            let next_id = cur_edge_ref.borrow().neighbor_id(cur_id).unwrap();

            // get amount/time_lock_delta we got with UpdateAddHtlc
            let amount_to_forward = payment_ref.borrow().path().borrow().get_hop_amount_to_forward(cur_edge_id).unwrap();
            let remaining_time = payment_ref.borrow().path().borrow().get_hop_remaining_time(cur_edge_id).unwrap();


            // calculate and check that we can actually forward
            if cur_edge_ref.borrow().get_balance(cur_id).unwrap() < amount_to_forward {
                info!{"{}: Payment {} failed at node {}: insufficient balance.", self.event_queue.now(), payment_ref.borrow().payment_id(), cur_node_ref.borrow().node_id()};
                return false;
            }


            let mut reply_messages = Vec::new();

            let forward_message = MessageType::UpdateAddHtlc{ amount: amount_to_forward, remaining_time: remaining_time, payment_ref: Rc::clone(&payment_ref) };
            reply_messages.push(forward_message);


            // And update channel state
            let old_state_ref = cur_edge_ref.borrow().channel_state();
            let old_state_id = old_state_ref.borrow().state_id();
            let old_node1_id = old_state_ref.borrow().node1_id();
            let old_node2_id = old_state_ref.borrow().node2_id();
            let old_node1_balance = old_state_ref.borrow().node1_balance();
            let old_node2_balance = old_state_ref.borrow().node2_balance();

            //info!{"old_node1_balance: {}, old_node2_balance: {}, amount_to_forward: {}", old_node1_balance, old_node2_balance, amount_to_forward}

            let new_node1_balance = if cur_id == old_node1_id {
                old_node1_balance-amount_to_forward
            } else {
                old_node1_balance+amount_to_forward
            };

            let new_node2_balance = if cur_id == old_node2_id {
                old_node2_balance-amount_to_forward
            } else {
                old_node2_balance+amount_to_forward
            };
            //info!{"new_node1_balance: {}, new_node2_balance: {}, amount_to_forward: {}", new_node1_balance, new_node2_balance, amount_to_forward}
            let capacity = cur_edge_ref.borrow().capacity();
            assert_eq!(capacity, old_node1_balance+old_node2_balance);
            assert_eq!(capacity, new_node1_balance+new_node2_balance);

            let new_state_id = old_state_id + 1;
            let new_state_ref = Rc::new(RefCell::new(ChannelState::new(
                        new_state_id,
                        old_node1_id,
                        old_node2_id,
                        new_node1_balance,
                        new_node2_balance
                        )));

            let commit_message = MessageType::CommitmentSigned { state_ref: new_state_ref, payment_ref: Rc::clone(&payment_ref) };
            reply_messages.push(commit_message);

            let next_sender = self.graph.get_node_ref(cur_id).unwrap();
            let next_receiver = self.graph.get_node_ref(next_id).unwrap();


            if payment_ref.borrow().is_last_malicious_node(Rc::clone(&next_sender)) {
                // we are the first malicious node
                // keep track of when we sent UpdateAddHtlc
                let cur_time = self.event_queue.now();
                let cur_payment_id = payment_ref.borrow().payment_id();
                let p_id = if let Some(old_payment_id) = payment_ref.borrow().retry_of() {
                    old_payment_id
                } else {
                    cur_payment_id
                };
                info!("{} | N {}: Last malicious node observed payment {} a first time.", self.event_queue.now(), cur_id, p_id);
                self.observed_update_sent_times.insert(p_id, cur_time);
            }
            self.queue_messages(next_sender, next_receiver, cur_edge_ref, reply_messages);
            return true;
        }
        false
    }

    fn next_payment_id(&mut self) -> PaymentId {
        let payment_id = self.next_payment_id;
        self.next_payment_id += 1;
        return payment_id;
    }

    fn get_first_malicious_node(&self, path_ref: PathRef) -> Option<NodeRef> {
        let nodes = path_ref.borrow().get_nodes();
        for n_id in nodes {
            if let Some(node_ref) = self.graph.get_node_ref(n_id) {
                if node_ref.borrow().is_malicious() {
                    return Some(node_ref);
                }
            }
        }
        None
    }

    fn get_first_malicious_node_pos(&self, path_ref: PathRef) -> Option<usize> {
        let nodes = path_ref.borrow().get_nodes();
        let mut pos = 0;
        for n_id in nodes {
            if let Some(node_ref) = self.graph.get_node_ref(n_id) {
                if node_ref.borrow().is_malicious() {
                    return Some(pos);
                }
            }
            pos += 1;
        }
        None
    }

    fn get_last_malicious_node(&self, path_ref: PathRef) -> Option<NodeRef> {
        let mut nodes = path_ref.borrow().get_nodes();
        nodes.reverse();
        for n_id in nodes {
            if let Some(node_ref) = self.graph.get_node_ref(n_id) {
                if node_ref.borrow().is_malicious() {
                    return Some(node_ref);
                }
            }
        }
        None
    }

    fn get_last_malicious_node_pos(&self, path_ref: PathRef) -> Option<usize> {
        let mut nodes = path_ref.borrow().get_nodes();
        let mut pos = path_ref.borrow().len()-1;
        nodes.reverse();
        for n_id in nodes {
            if let Some(node_ref) = self.graph.get_node_ref(n_id) {
                if node_ref.borrow().is_malicious() {
                    return Some(pos);
                }
            }
            pos -= 1;
        }
        None
    }

    fn calculate_most_central(&self, count: u32) {
        let mut node_counts: HashMap<NodeId, u32> = HashMap::new();
        for _ in 0..10000 {
            let amount = 1000;
            let source = self.graph.get_random_node().unwrap();
            let destination = self.graph.get_random_node().unwrap();

            let source_id = source.borrow().node_id();
            let destination_id = destination.borrow().node_id();
            let max_time_lock = CONFIG.read().unwrap().default_max_time_lock();

            let mut finder = PathFinder::new(source_id, destination_id, amount, max_time_lock, Box::new(self.graph.clone()));
            if let Some((path, _, _)) = finder.find_path() {
                let nodes = path.get_nodes();
                for n in nodes {
                    let n_count = node_counts.entry(n).or_insert(0);
                    *n_count += 1;
                }
            }

        }
        let mut rank_map: BTreeMap<u32, Vec<NodeId>> = BTreeMap::new();

        for (n, c) in node_counts.clone() {
            let entry = rank_map.entry(c).or_insert(Vec::new());
            entry.push(n);
        }

        let mut i = 0;
        let mut iter = rank_map.iter().rev();
        let mut file = File::create("most_central_nodes.csv").unwrap();
        let max_count = std::cmp::min(count, node_counts.len() as u32);
        while i < max_count {
            if let Some((c, list)) = iter.next() {
                for node in list {
                    println!("c: {}, node: {}", c, node);
                    let _ = write!{file, "{}\n", node};
                    i += 1;
                }
            }
        }

    }

}

