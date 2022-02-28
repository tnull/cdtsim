use crate::graph::{NodeRef, ChannelStateRef, PathRef};
use std::rc::Rc;
use std::cell::RefCell;
use std::cmp::Ordering;

pub type PaymentId = u32;
pub type PaymentRef = Rc<RefCell<Payment>>;

#[derive(Eq,PartialEq,Debug,Clone)]
pub enum MessageType {
    UpdateAddHtlc { amount: u64, remaining_time: u16, payment_ref: PaymentRef },
    UpdateFailHtlc { payment_ref: PaymentRef},
    UpdateFulfillHtlc { payment_ref: PaymentRef },
    CommitmentSigned { state_ref: ChannelStateRef, payment_ref: PaymentRef },
    RevokeAndAck { state_ref: ChannelStateRef, payment_ref: PaymentRef },
    TestDummy,
}

#[derive(Debug,Clone)]
pub struct Payment {
    payment_id: PaymentId,
    retry_of: Option<PaymentId>,
    source: NodeRef,
    destination: NodeRef,
    amount: u64,
    pub max_time_lock: u16,
    failed: bool,
    path: PathRef,
    current_hop: NodeRef,
    first_malicious_node: Option<NodeRef>,
    last_malicious_node: Option<NodeRef>,
}

impl Payment {
    pub fn new(payment_id: PaymentId, retry_of: Option<PaymentId>, source: NodeRef, destination: NodeRef, amount: u64, max_time_lock: u16, path: PathRef, first_malicious_node: Option<NodeRef>, last_malicious_node: Option<NodeRef>) -> Self {
        let failed = false;
        let current_hop = Rc::clone(&source);
        Self {
            payment_id,
            retry_of,
            source,
            destination,
            amount,
            max_time_lock,
            failed,
            path,
            current_hop,
            first_malicious_node,
            last_malicious_node,
        }
    }

    pub fn source(&self) -> NodeRef {
        Rc::clone(&self.source)
    }

    pub fn destination(&self) -> NodeRef {
        Rc::clone(&self.destination)
    }

    pub fn amount(&self) -> u64 {
        self.amount
    }


    pub fn payment_id(&self) -> PaymentId {
        self.payment_id
    }

    pub fn retry_of(&self) -> Option<PaymentId> {
        self.retry_of
    }

    pub fn is_retry(&self) -> bool {
        self.retry_of.is_some()
    }


    pub fn path(&self) -> PathRef {
        Rc::clone(&self.path)
    }

    pub fn get_current_hop(&self) -> NodeRef {
        Rc::clone(&self.current_hop)
    }

    pub fn set_current_hop(&mut self, node_ref: NodeRef) {
        self.current_hop = node_ref;
    }

    pub fn set_failed(&mut self) {
        self.failed = true;
    }

    pub fn has_failed(&self) -> bool {
        self.failed
    }

    pub fn is_first_malicious_node(&self, node_ref: NodeRef) -> bool {
        if let Some(m_ref) = self.first_malicious_node.clone() {
            return node_ref == m_ref
        }
        false
    }

    pub fn is_last_malicious_node(&self, node_ref: NodeRef) -> bool {
        if let Some(m_ref) = self.last_malicious_node.clone() {
            return node_ref == m_ref
        }
        false
    }
}

impl PartialEq for Payment {
    fn eq(&self, other: &Self) -> bool {
        self.payment_id == other.payment_id
    }
}

impl Eq for Payment {}

impl Ord for Payment {
    fn cmp(&self, other: &Self) -> Ordering {
        self.payment_id.cmp(&other.payment_id)
    }
}

impl PartialOrd for Payment {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
