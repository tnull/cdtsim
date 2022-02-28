#[allow(unused_imports)] 
use log::{info,debug,trace};
use crate::RNG;

use maxminddb::geoip2;
use std::str::FromStr;
use std::net::SocketAddr;
use rand::{
    distributions::{Distribution, Standard},
    Rng,
};
use std::hash::{Hash, Hasher};

use std::fmt;
use serde::Deserialize;

use lngraphparser as lngp;

#[derive(Debug, Eq, PartialEq, PartialOrd, Clone, Deserialize, Copy)]
pub enum Region {
    NA,
    SA,
    EU,
    AF,
    AS,
    OC,
    CN,
}

impl fmt::Display for Region {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str_region = match self {
            Region::NA => "NA",
            Region::SA => "SA",
            Region::EU => "EU",
            Region::AF => "AF",
            Region::AS => "AS",
            Region::OC => "OC",
            Region::CN => "CN",
        };
        write!(f, "{}", str_region)
    }
}

impl FromStr for Region {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "NA" => Ok(Region::NA),
            "SA" => Ok(Region::SA),
            "EU" => Ok(Region::EU),
            "AF" => Ok(Region::AF),
            "AS" => Ok(Region::AS),
            "OC" => Ok(Region::OC),
            "CN" => Ok(Region::CN),
            _ => Err( () ),
        }
    }
}

impl Hash for Region {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_string().hash(state)
    }
}

impl Distribution<Region> for Standard {
    fn sample<R: Rng + ?Sized>(&self, _rng: &mut R) -> Region {
        // FIXME: not sure why this works while the normal way leads to non-determinic behavior
        let mut rng2 = RNG.lock().unwrap();
        match (*rng2).gen_range(0, 100) {
            0..=48 => Region::EU,
            49..=89 => Region::NA,
            90..=94 => Region::AS,
            95..=96 => Region::OC,
            97 => Region::SA,
            98 => Region::CN,
            _ => Region::AF,
        }
    }
}

pub struct GeoReader {
    reader: maxminddb::Reader<Vec<u8>>
}

impl GeoReader {
    pub fn try_new(db_path: &String) -> Option<Self> {
        if let Ok(reader) = maxminddb::Reader::open_readfile(db_path) {
            return Some(Self { reader });
        }
        None
    }

    pub fn get_region(&self, parsed_node: lngp::Node) -> Region {
        for entry in parsed_node.addresses {
            if let Ok(addr) = SocketAddr::from_str(&entry.addr) {
                //debug!("Addr: {:?}", addr);
                let country_res: Result<geoip2::Country,_> = self.reader.lookup(addr.ip());
                if let Ok(res) = country_res {
                    //debug!("res {:?}", res);
                    if let Some(country) = res.country {
                        if let Some(code) = country.iso_code {
                            if let Ok(region_code) = Region::from_str(&code) {
                                if region_code == Region::CN {
                                    return Region::CN;
                                }
                            }
                        }
                    }

                    if let Some(continent) = res.continent {
                        if let Some(code) = continent.code {
                            if let Ok(region_code) = Region::from_str(&code) {
                                return region_code;
                            } 
                        }
                    }
                }
            }
        }
        // if no other region was found, return a random one.
        let rand_region: Region = rand::random();
        rand_region
    }
}


