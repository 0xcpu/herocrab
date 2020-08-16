use std::collections::HashSet;

use herocrab::windows::analysis::{
    is_any_unwanted_process_running,
    is_any_unwanted_top_window_existent,
    is_any_unwanted_mutant_existent,
    is_any_unwanted_symlink_existent,
    is_debugged_peb,
    is_remotely_debugged,
    is_debugged_invalid_handle,
    is_debugged_hw_bp,
    is_debugged_int_2d,
    is_debugged_int_3
};

use winapi::shared::minwindef::DWORD;


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

pub fn run_analysis(config: &serde_json::Value) {
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
    let task_is_debug_inv_h = Task {
        name: "Debugged invalid handle",
        config_field_name: None,
        func: AnalysisFn::Arg0(is_debugged_invalid_handle),
    };
    let task_is_debug_hw = Task {
        name: "Hw breakpoins",
        config_field_name: None,
        func: AnalysisFn::Arg0(is_debugged_hw_bp),
    };
    let task_is_debug_int_2d = Task {
        name: "Int 0x2d",
        config_field_name: None,
        func: AnalysisFn::Arg0(is_debugged_int_2d),
    };
    let task_is_debug_int_3 = Task {
        name: "Int 3",
        config_field_name: None,
        func: AnalysisFn::Arg0(is_debugged_int_3),
    };
    tasks.push(&task_processes);
    tasks.push(&task_windows);
    tasks.push(&task_mutants);
    tasks.push(&task_symlinks);
    tasks.push(&task_is_debug_peb);
    tasks.push(&task_is_debug_rem);
    tasks.push(&task_is_debug_inv_h);
    tasks.push(&task_is_debug_hw);
    tasks.push(&task_is_debug_int_2d);
    tasks.push(&task_is_debug_int_3);

    for t in &tasks {
        print!("Testing: <{:^30}> ", t.name);
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
                Ok(true)  => println!("{:>40}", "Detected"),
                Ok(false) => println!("{:>40}", "Not detected"),
                Err(err)  => println!("Oops: {}", err),
            }
        } else {
            let func = match t.func {
                AnalysisFn::Arg0(f) => f,
                _                   => panic!("wrong function type"),
            };
            match func() {
                Ok(true)  => println!("{:>40}", "Detected"),
                Ok(false) => println!("{:>40}", "Not detected"),
                Err(err)  => println!("Oops: {}", err),
            }
        }
    }
}