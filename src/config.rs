#[derive(Debug, Clone)]
pub struct Config {
    lngraph_path: String,
    geoip2_db_path: String,
    latency_data_path: String,
    processing_delay: f32,
    default_max_time_lock: u16,
    default_time_lock_delta: u16,
    default_fee_base_msat: u64,
    default_fee_rate_milli_msat: u64, 
}

impl Config {
    pub fn new() -> Self {
        let lngraph_path = "lngraph.json".to_string();
        let geoip2_db_path = "GeoLite2-Country.mmdb".to_string();
        let latency_data_path = "data_parsed_latencies.csv".to_string();
        let processing_delay = 10.0;
        let default_max_time_lock = 2016;
        let default_time_lock_delta = 40;
        let default_fee_base_msat = 1000;
        let default_fee_rate_milli_msat = 1;
        Self { lngraph_path, geoip2_db_path, latency_data_path, processing_delay, default_max_time_lock,  default_time_lock_delta, default_fee_base_msat, default_fee_rate_milli_msat }
    }

    pub fn lngraph_path(&self) -> &String{
        &self.lngraph_path
    }

    pub fn geoip2_db_path(&self) -> &String{
        &self.geoip2_db_path
    }

    pub fn latency_data_path(&self) -> &String{
        &self.latency_data_path
    }

    pub fn processing_delay(&self) -> f32 {
        self.processing_delay
    }

    pub fn default_max_time_lock(&self) -> u16 {
        self.default_max_time_lock
    }

    pub fn default_time_lock_delta(&self) -> u16 {
        self.default_time_lock_delta
    }

    pub fn default_fee_base_msat(&self) -> u64 {
        self.default_fee_base_msat
    }

    pub fn default_fee_rate_milli_msat(&self) -> u64 {
        self.default_fee_rate_milli_msat
    }
}

