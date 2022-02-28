use crate::geo::Region;

use std::fs::File;
use std::collections::HashMap;
use std::rc::Rc;

use std::process;
use serde::Deserialize;
use rand::seq::SliceRandom;
use rand_distr::{Normal, Distribution};

use crate::CONFIG;
use crate::RNG;
use crate::util;

pub type LatencyDistributionRef = Rc<LatencyDistribution>;

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub struct LatencyMeasurement {
    #[serde(rename = "region")]
    pub meas_region: Region,
    #[serde(rename = "destRegion")]
    pub node_region: Region,
    #[serde(rename = "packetTransmit")]
    pub packet_transmit: u32,
    #[serde(rename = "packetReceive")]
    pub packet_receive: u32,
    #[serde(rename = "packetLossCount")]
    pub packet_loss_count: u32,
    #[serde(rename = "packetLossRate")]
    pub packet_loss_rate: f32,
    #[serde(rename = "rttMin")]
    pub rtt_min: f32,
    #[serde(rename = "rttAvg")]
    pub rtt_avg: f32, 
    #[serde(rename = "rttMax")]
    pub rtt_max: f32, 
    #[serde(rename = "rttMdev")]
    pub rtt_mdev: f32,
    #[serde(rename = "packetDuplicateCount")]
    pub packet_duplicate_count: u32,
    #[serde(rename = "packetDuplicateRate")]
    pub packet_duplicate_rate: f32,
}

pub struct LatencyModel {
    measurements: HashMap<(Region, Region), Vec<LatencyMeasurement>>
}

impl LatencyModel {
    pub fn new() -> Self {
        let mut measurements = HashMap::new();
        
        let file = File::open(CONFIG.read().unwrap().latency_data_path()).unwrap_or_else(|err| {
            eprintln!("Could not open latency measurements!: {}", err);
            process::exit(-1);
        });
        let mut rdr = csv::Reader::from_reader(file);
        for deserialized in rdr.deserialize() {
            let result: Result<LatencyMeasurement, _> = deserialized;
            match result {
                Err(_) => continue,
                Ok(meas) => {
                    let meas_region = meas.meas_region.clone();
                    let node_region = meas.node_region.clone();
                    let key = util::ordered_tuple_key(meas_region, node_region);
                    let prior_measurements = measurements.entry(key).or_insert(Vec::new());
                    prior_measurements.push(meas);
                }
            }
        }
        Self { measurements }
    }

    pub fn rand_meas(&self, reg0: Region, reg1: Region) -> Option<LatencyMeasurement> {
        let key = util::ordered_tuple_key(reg0, reg1);
        if let Some(reg_measurements) = self.measurements.get(&key) {
            let mut rng = RNG.lock().unwrap();
            if let Some(rand_elem) = reg_measurements.choose(&mut *rng) {
                return Some((*rand_elem).clone());
            }
        }
        return None
    }

    pub fn rand_lat_dist(&self, reg0: Region, reg1: Region) -> Option<LatencyDistribution> {
        if let Some(rand_meas) = self.rand_meas(reg0, reg1) {
            let lat_dist = LatencyDistribution::from_measurement(rand_meas);
            return Some(lat_dist);
        }
        return None
    }
}

#[derive(Debug, Clone)]
pub struct LatencyDistribution {
    latency_dist: Normal<f32>,
    lat_min: f32,
    lat_max: f32,
}

impl LatencyDistribution {
    pub fn from_measurement(meas: LatencyMeasurement) -> Self {
        // we assume 1*rtt = 2*(end-to-end 'link' latency)
        let lat_mean = meas.rtt_avg/2.0;
        let lat_stddev = meas.rtt_mdev/2.0;
        let lat_min = meas.rtt_min/2.0;
        let lat_max = meas.rtt_max/2.0;
        let latency_dist = Normal::new(lat_mean, lat_stddev).unwrap();
        Self { latency_dist, lat_min, lat_max}
    }

    pub fn sample(&self) -> f32 {
        let mut rng = RNG.lock().unwrap();
        let res = self.latency_dist.sample(&mut *rng);
        let processing_delay = CONFIG.read().unwrap().processing_delay();
        if res > self.lat_max {
            return self.lat_max + processing_delay;
        }
        if res < self.lat_min {
            return self.lat_min + processing_delay;
        }
        res + processing_delay
    }
}


