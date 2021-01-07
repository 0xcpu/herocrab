use std::collections::{HashSet, HashMap};

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
    is_debugged_int_3,
    is_debugged_global_flag,
    is_debugged_guard_page,
    is_any_module_hooked,
    is_debugged_debug_flags,
    is_debugged_debug_port,
    is_kernel_debugger_present,
    does_thread_hide_fail,
    is_objinfo_numobj_hooked
};

use winapi::shared::minwindef::DWORD;


type AnalysisFnArg0   = fn() -> Result<bool, DWORD>;
type AnalysisFnArg1Hs = fn(&HashSet<String>) -> Result<bool, DWORD>;
type AnalysisFnArg1Hm = fn(&HashMap<String, Vec<String>>) -> Result<bool, DWORD>;

enum AnalysisFn {
    Arg0(AnalysisFnArg0),
    Arg1Hs(AnalysisFnArg1Hs),
    Arg1Hm(AnalysisFnArg1Hm)
}

struct Task {
    name: &'static str,
    config_field_name: Option<&'static str>,
    func: AnalysisFn,
}

pub fn run_analysis(config: &serde_json::Value) {
    // there should be a way to write this better... macros? o.O
    let mut tasks = Vec::new();
    let task_processes = Task {
        name: "Processes",
        config_field_name: Some("processes"),
        func: AnalysisFn::Arg1Hs(is_any_unwanted_process_running),
    };
    let task_windows = Task {
        name: "Top windows",
        config_field_name: Some("top_windows"),
        func: AnalysisFn::Arg1Hs(is_any_unwanted_top_window_existent),
    };
    let task_mutants = Task {
        name: "Mutants",
        config_field_name: Some("mutants"),
        func: AnalysisFn::Arg1Hs(is_any_unwanted_mutant_existent),
    };
    let task_symlinks = Task {
        name: "Symlinks",
        config_field_name: Some("symlinks"),
        func: AnalysisFn::Arg1Hs(is_any_unwanted_symlink_existent),
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
    let task_is_debug_global_flag = Task {
        name: "NtGlobalFlag",
        config_field_name: None,
        func: AnalysisFn::Arg0(is_debugged_global_flag),
    };
    let task_is_debug_guard_page = Task {
        name: "Debug guard page",
        config_field_name: None,
        func: AnalysisFn::Arg0(is_debugged_guard_page),
    };
    let task_is_api_hooked = Task {
        name: "Hooked APIs",
        config_field_name: Some("modules"),
        func: AnalysisFn::Arg1Hm(is_any_module_hooked),
    };
    let task_is_debug_proc_flags = Task {
        name: "Process info debug flags",
        config_field_name: None,
        func: AnalysisFn::Arg0(is_debugged_debug_flags),
    };
    let task_is_debug_port = Task {
        name: "Debug port",
        config_field_name: None,
        func: AnalysisFn::Arg0(is_debugged_debug_port),
    };
    let task_is_kernel_debug = Task {
        name: "Is kernel debugged",
        config_field_name: None,
        func: AnalysisFn::Arg0(is_kernel_debugger_present),
    };
    let task_is_thread_hidden = Task {
        name: "Is thread hidden",
        config_field_name: None,
        func: AnalysisFn::Arg0(does_thread_hide_fail),
    };
    let task_is_objinfo_hooked = Task {
        name: "TotalNumberOfObjects hooked",
        config_field_name: None,
        func: AnalysisFn::Arg0(is_objinfo_numobj_hooked),
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
    tasks.push(&task_is_debug_global_flag);
    tasks.push(&task_is_debug_guard_page);
    tasks.push(&task_is_api_hooked);
    tasks.push(&task_is_debug_proc_flags);
    tasks.push(&task_is_debug_port);
    tasks.push(&task_is_kernel_debug);
    tasks.push(&task_is_thread_hidden);
    tasks.push(&task_is_objinfo_hooked);
    for t in &tasks {
        print!("Testing: <{:^30}> ", t.name);
        if let Some(cn) = t.config_field_name {
            if config["windows"][cn].is_array() {
                let arg = config["windows"][cn].as_array()
                                               .unwrap()
                                               .iter()
                                               .map(|v| v.as_str()
                                                         .unwrap()
                                                         .to_string())
                                               .collect();
                let func = match t.func {
                    AnalysisFn::Arg1Hs(f) => f,
                    _                     => panic!("wrong function type"),
                };
                match func(&arg) {
                    Ok(true)  => println!("{:>40}", "Detected"),
                    Ok(false) => println!("{:>40}", "Not detected"),
                    Err(err)  => println!("Oops: {}", err),
                }
            } else if config["windows"][cn].is_object() {
                let mut arg: HashMap<String, Vec<String>> = HashMap::new();
                for (key, value) in config["windows"][cn].as_object().unwrap() {
                    arg.insert(key.to_string(), value.as_array()
                                                     .unwrap()
                                                     .iter()
                                                     .map(|v| v.as_str()
                                                               .unwrap()
                                                               .to_string())
                                                     .collect());
                }

                let func = match t.func {
                    AnalysisFn::Arg1Hm(f) => f,
                    _                     => panic!("wrong function type"),
                };
                match func(&arg) {
                    Ok(true)  => println!("{:>40}", "Detected"),
                    Ok(false) => println!("{:>40}", "Not detected"),
                    Err(err)  => println!("Oops: {}", err),
                }
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