extern crate serde_json;
extern crate clap;

use std::{fs, thread, sync::Arc};
use clap::{App, Arg};

mod anti_analysis;

use anti_analysis::win_anti_analysis;


fn main() {
    let matches = App::new("herocrab")
                            .version("0.1")
                            .author("0xcpu")
                            .about("Checks which properties of your system are detectable by ex: malware")
                            .arg(Arg::with_name("config")
                                    .short("c")
                                    .long("config")
                                    .value_name("FILE")
                                    .default_value("herocrab.conf")
                                    .help("Set path to config file")
                                    .takes_value(true))
                            .get_matches();

    let config_file = matches.value_of("config").unwrap();
    let config = fs::read_to_string(config_file)
                                    .expect("failed reading conf file");
    let config = Arc::<serde_json::Value>::new(serde_json::from_str(&config).unwrap());

    let mut threads = Vec::new();
    let routines = [&win_anti_analysis::run_analysis];
    
    for i in 0..routines.len() {
        let c = config.clone();
        threads.push(thread::spawn(move || {
            let routine = routines[i];
            routine(&c);
        }));
    }
    for t in threads {
        let _ = t.join();
    }
}
