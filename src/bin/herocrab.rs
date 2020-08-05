extern crate serde_json;
extern crate clap;

use std::{fs, thread, sync::Arc};
use clap::{App, Arg};
use std::collections::HashSet;

#[cfg(windows)]
use herocrab::windows::analysis::{
    is_any_unwanted_process_running,
    is_any_unwanted_top_window_existent,
    is_any_unwanted_mutant_existent,
    is_any_unwanted_symlink_existent
};
#[cfg(windows)]
use winapi::shared::minwindef::DWORD;

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
    let routines = [&run_analysis];
    
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

type AnalysisFn = fn(&HashSet<String>) -> Result<bool, DWORD>;

struct Task {
    name: &'static str,
    func: AnalysisFn,
}

fn run_analysis(config: &serde_json::Value) {
    let mut tasks = Vec::new();
    let task_processes = Task {
        name: "processes",
        func: is_any_unwanted_process_running,
    };
    let task_windows = Task {
        name: "top_windows",
        func: is_any_unwanted_top_window_existent,
    };
    let task_mutants = Task {
        name: "mutants",
        func: is_any_unwanted_mutant_existent,
    };
    let task_symlinks = Task {
        name: "symlinks",
        func: is_any_unwanted_symlink_existent,
    };
    tasks.push(&task_processes);
    tasks.push(&task_windows);
    tasks.push(&task_mutants);
    tasks.push(&task_symlinks);

    for t in &tasks {
        print!("Testing: <{:^20}> ", t.name);
        let unwanted: HashSet<String> = config["windows"][t.name].as_array()
                                                                 .unwrap()
                                                                 .iter()
                                                                 .map(|v| v.as_str().unwrap().to_string())
                                                                 .collect();
        let func: AnalysisFn = t.func;
        match func(&unwanted) {
            Ok(true)  => println!("{:>30}", "Detected"),
            Ok(false) => println!("{:>30}", "Not detected"),
            Err(err)  => println!("Oops: {}", err),
        }
    }
}