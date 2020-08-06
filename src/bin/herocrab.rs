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
    is_any_unwanted_symlink_existent,
    is_debugged_peb,
    is_remotely_debugged
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

type AnalysisFnArg0 = fn() -> Result<bool, DWORD>;
type AnalysisFnArg1 = fn(&HashSet<String>) -> Result<bool, DWORD>;

enum AnalysisFn {
    Arg0(AnalysisFnArg0),
    Arg1(AnalysisFnArg1),
}

struct Task {
    name: &'static str,
    config_field_name: Option<&'static str>, // TODO: Maybe use a default value?
    func: AnalysisFn,
}

fn run_analysis(config: &serde_json::Value) {
    // there should be a way to write this better... macros? o.O
    let mut tasks = Vec::new();
    let task_processes = Task {
        name: "Processes",
        config_field_name: Some("processes"),
        func: AnalysisFn::Arg1(is_any_unwanted_process_running),
    };
    let task_windows = Task {
        name: "Top windows",
        config_field_name: Some("top_windows"),
        func: AnalysisFn::Arg1(is_any_unwanted_top_window_existent),
    };
    let task_mutants = Task {
        name: "Mutants",
        config_field_name: Some("mutants"),
        func: AnalysisFn::Arg1(is_any_unwanted_mutant_existent),
    };
    let task_symlinks = Task {
        name: "Symlinks",
        config_field_name: Some("symlinks"),
        func: AnalysisFn::Arg1(is_any_unwanted_symlink_existent),
    };
    let task_is_debug_peb = Task {
        name: "PEB IsDebugged",
        config_field_name: None,
        func: AnalysisFn::Arg0(is_debugged_peb),
    };
    let task_is_debug_rem = Task {
        name: "Remote Debugging",
        config_field_name: None,
        func: AnalysisFn::Arg0(is_remotely_debugged),
    };
    tasks.push(&task_processes);
    tasks.push(&task_windows);
    tasks.push(&task_mutants);
    tasks.push(&task_symlinks);
    tasks.push(&task_is_debug_peb);
    tasks.push(&task_is_debug_rem);

    for t in &tasks {
        print!("Testing: <{:^20}> ", t.name);
        if let Some(cn) = t.config_field_name {
            let unwanted: HashSet<String> = config["windows"][cn].as_array()
                                                                 .unwrap()
                                                                 .iter()
                                                                 .map(|v| v.as_str()
                                                                           .unwrap()
                                                                           .to_string())
                                                                 .collect();
            let func = match t.func {
                AnalysisFn::Arg1(f) => f,
                _                   => panic!("wrong function type"),
            };
            match func(&unwanted) {
                Ok(true)  => println!("{:>30}", "Detected"),
                Ok(false) => println!("{:>30}", "Not detected"),
                Err(err)  => println!("Oops: {}", err),
            }
        } else {
            let func = match t.func {
                AnalysisFn::Arg0(f) => f,
                _                   => panic!("wrong function type"),
            };
            match func() {
                Ok(true)  => println!("{:>30}", "Detected"),
                Ok(false) => println!("{:>30}", "Not detected"),
                Err(err)  => println!("Oops: {}", err),
            }
        }
    }
}