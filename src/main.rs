use clap::{Arg, App, value_t};

use std::process;
use log::LevelFilter;
#[allow(unused_imports)] 
use log::{info,debug,trace};

fn main() {
    simple_logging::log_to_file("cdtsim.log", LevelFilter::Info).unwrap_or_else(|err| {
        eprintln!("Could not open logfile: {}", err);
        process::exit(-1);
    });


    let matches = App::new("CDTSIM")
                          .version("0.1")
                          .author("Elias Rohrer <elias.rohrer@tu-berlin.de>")
                          .arg(Arg::with_name("run")
                               .short("r")
                               .long("run")
                               .value_name("NUM")
                               .help("Sets the run number / seed value for the simulation.")
                               .takes_value(true))
                          .arg(Arg::with_name("amount")
                               .short("a")
                               .long("amount")
                               .value_name("MSAT")
                               .help("Determines the amount (in milli-satoshi) for each simulated payment.")
                               .takes_value(true))
                          .arg(Arg::with_name("num_tries")
                               .short("t")
                               .long("num_tries")
                               .value_name("NUM")
                               .help("Sets the number of payment attempts that are tried in each simulation.")
                               .takes_value(true))
                          .arg(Arg::with_name("adversary")
                               .short("s")
                               .long("adversary")
                               .value_name("mcentral/mrandom/lnbig")
                               .help("Sets the adversarial scenario.")
                               .takes_value(true))
                          .arg(Arg::with_name("num_malicious")
                               .short("m")
                               .long("num_malicious")
                               .value_name("NUM")
                               .help("Sets the number of malicious nodes.")
                               .takes_value(true))
                          .get_matches();


    let run = value_t!(matches.value_of("run"), u64).unwrap_or_else(|_| 23);
    let amount = value_t!(matches.value_of("amount"), u64).unwrap_or_else(|_| 1000);
    let num_tries = value_t!(matches.value_of("num_tries"), u32).unwrap_or_else(|_| 1000);
    let adversary = matches.value_of("adversary").unwrap_or("mcentral");
    let num_malicious = value_t!(matches.value_of("num_malicious"), u32).unwrap_or_else(|_| 10);
    match adversary {
        "mcentral" => {
            info!("Setting up adversary controlling {} most central nodes.", num_malicious);
        },
        "mrandom" => {
            info!("Setting up adversary controlling {} random nodes.", num_malicious);
        },
        "lnbig" => {
            info!("Setting up adversary controlling LNBIG nodes.");
        },
        _ => {
            eprintln!("Unkown adversarial scenarion: {}", adversary);
            process::exit(-1);
        }
    }

    if let Some(mut sim) = cdtsim::Simulation::new(run, amount, num_tries, adversary.to_string(), num_malicious) {
        sim.run();
    }
}
