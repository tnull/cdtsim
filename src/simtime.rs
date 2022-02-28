use std::cmp::Ordering;
use std::ops::{Add, Sub, AddAssign};

use std::fmt;

#[derive(Debug,Copy,Clone)]
pub struct SimTime (u64);

static SIMTIME_SCALING_FACTOR_SECS: f32 = 1000000.0; // We're assuming SimTime to be in nano secs.
static SIMTIME_SCALING_FACTOR_MILLIS: f32 = 1000.0; 

impl SimTime {
    pub fn as_secs(&self) -> f32 {
        self.0 as f32 / SIMTIME_SCALING_FACTOR_SECS
    }

    pub fn as_millis(&self) -> f32 {
        self.0 as f32 / SIMTIME_SCALING_FACTOR_MILLIS
    }

    pub fn as_nanos(&self) -> f32 {
        self.0 as f32
    }

    pub fn from_secs(secs: f32) -> Self {
        let nanos = secs * SIMTIME_SCALING_FACTOR_SECS;
        SimTime (nanos as u64)
    }

    pub fn from_millis(millis: f32) -> Self {
        let nanos = millis * SIMTIME_SCALING_FACTOR_MILLIS;
        SimTime (nanos as u64)
    }

    pub fn from_nanos(nanos: f32) -> Self {
        SimTime (nanos as u64)
    }
}

impl Ord for SimTime {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for SimTime {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for SimTime {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for SimTime {}

impl Add for SimTime {
    type Output = SimTime;
    fn add(self, other: SimTime) -> Self {
        Self (self.0 + other.0)
    }
}

impl AddAssign for SimTime {
    fn add_assign(&mut self, other: Self) {
        *self = Self ( self.0 + other.0);
    }
}

impl Sub for SimTime {
    type Output = SimTime;
    fn sub(self, other: SimTime) -> Self {
        if other.0 > self.0 {
            return Self(0);
        }
        Self (self.0 - other.0)
    }
}

impl fmt::Display for SimTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simtime_conversion_works() {
        let secs = 1.0;
        let millis = 1000.0;
        let s0 = SimTime::from_secs(secs);
        let s1 = SimTime::from_millis(millis);
        assert_eq!(millis, s0.as_millis());
        assert_eq!(secs, s0.as_secs());
        assert_eq!(s0,s1);
    }

    #[test]
    fn simtime_cmp_works() {
        let smaller_millis = 1000.0;
        let greater_millis = 2000.0;
        let s_smaller = SimTime::from_millis(smaller_millis);
        let s_greater = SimTime::from_millis(greater_millis);
        assert!(s_smaller < s_greater);
        assert_ne!(s_smaller, s_greater);
    }

    #[test]
    fn simtime_addition_works() {
        let s0 = SimTime::from_secs(1.0);
        let s1 = SimTime::from_secs(2.0);
        let s2 = s0+s1;
        assert_eq!(3.0,s2.as_secs());
        assert_eq!(s2.as_secs(),s0.as_secs()+s1.as_secs());
    }

    #[test]
    fn simtime_substraction_works() {
        let s0 = SimTime::from_secs(1.0);
        let s1 = SimTime::from_secs(2.0);
        let s2 = s0-s0;
        let s3 = s0-s1;
        let s4 = s1-s0;
        assert_eq!(0.0,s2.as_secs());
        assert_eq!(0.0,s3.as_secs());
        assert_eq!(1.0,s4.as_secs());
        assert_eq!(s4.as_secs(),s1.as_secs()-s0.as_secs());
    }
}
