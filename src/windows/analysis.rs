extern crate widestring;
extern crate winapi;
extern crate ntapi;

use std::collections::HashSet;
use std::mem;

use winapi::shared::{
    minwindef::FALSE,
    minwindef::MAX_PATH,
    minwindef::TRUE,
    minwindef::DWORD,
    minwindef::LPARAM,
    ntdef::HANDLE,
    ntdef::NULL,
    windef::HWND,
    winerror::ERROR_FILE_NOT_FOUND
};
use winapi::um::winnt::{
    SYNCHRONIZE, GENERIC_READ, GENERIC_WRITE, FILE_SHARE_WRITE, FILE_SHARE_READ, FILE_ATTRIBUTE_NORMAL
};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};
use winapi::um::winuser::{EnumWindows, GetWindowTextW, GetWindowTextLengthW};
use winapi::um::synchapi::OpenMutexW;
use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
use winapi::um::debugapi::CheckRemoteDebuggerPresent;
use winapi::um::processthreadsapi::GetCurrentProcess;

use ntapi::ntpsapi::NtCurrentPeb;

/// Collect running processes
pub fn get_processes_names() -> Result<HashSet<String>, DWORD> {
    let h_snapshot: HANDLE = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if h_snapshot == INVALID_HANDLE_VALUE {
        unsafe {
            return Err(GetLastError());
        }
    }

    let mut proc_entry = PROCESSENTRY32W {
        dwSize: mem::size_of::<PROCESSENTRY32W>() as u32,
        cntUsage: 0,
        th32ProcessID: 0,
        th32DefaultHeapID: 0,
        th32ModuleID: 0,
        cntThreads: 0,
        th32ParentProcessID: 0,
        pcPriClassBase: 0,
        dwFlags: 0,
        szExeFile: [0; MAX_PATH],
    };
    unsafe {
        if Process32FirstW(h_snapshot, &mut proc_entry) == FALSE {
            CloseHandle(h_snapshot);
    
            return Err(GetLastError());
        }
    }

    let mut processes: HashSet<String> = HashSet::new();
    let process_name = String::from_utf16(&proc_entry.szExeFile).unwrap();
    processes.insert(process_name.trim_end_matches("\x00").to_string());

    while unsafe { Process32NextW(h_snapshot, &mut proc_entry) } == TRUE {
        let process_name = String::from_utf16(&proc_entry.szExeFile).unwrap();
        processes.insert(process_name.trim_end_matches("\x00").to_string());
    }

    unsafe { CloseHandle(h_snapshot) };

    Ok(processes)
}

/// Check if any process name in `unwanted_procs_names`
/// is present in the set of process names in the system.
pub fn is_any_unwanted_process_running(
    unwanted_procs_names: &HashSet<String>
) -> Result<bool, DWORD> {
    let processes_names = get_processes_names()?;
    
    Ok(unwanted_procs_names.is_disjoint(&processes_names) == false)
}

extern "system" fn enum_top_windows_cb(h_wnd: HWND, l_param: LPARAM) -> i32 {
    let top_windows_names: &mut HashSet<String> = unsafe { &mut *(l_param as *mut HashSet<String>) };
    let top_window_name_len = unsafe { GetWindowTextLengthW(h_wnd) };
    let mut top_window_name = vec![0u16; (top_window_name_len + 1) as usize];

    unsafe {
        if GetWindowTextW(h_wnd, top_window_name.as_mut_ptr(), top_window_name_len + 1) != 0 {
            top_windows_names.insert(String::from_utf16(&top_window_name).unwrap().trim_end_matches("\x00").to_string());
         }
    }

    TRUE
}

pub fn get_top_window_names() -> Result<HashSet<String>, DWORD> {
    let mut top_window_names: HashSet<String> = HashSet::new();
    let p_top_window_names: LPARAM = &mut top_window_names as *mut HashSet<String> as LPARAM;

    unsafe {
        if EnumWindows(Some(enum_top_windows_cb), p_top_window_names) == 0 {
            return Err(GetLastError());
        }
    }

    Ok(top_window_names)
}

pub fn is_any_unwanted_top_window_existent(
    unwanted_top_windows_names: &HashSet<String>
) -> Result<bool, DWORD> {
    let top_window_names = get_top_window_names()?;

    for twn in &top_window_names {
        for utwn in unwanted_top_windows_names {
            if let Some(_) = twn.find(utwn) {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

pub fn is_mutant_existent(mutant_name: &String) -> Result<bool, DWORD> {
    let mut w_mutant_name = widestring::U16String::from_str(mutant_name);
    w_mutant_name.push_os_str("\x00");
    let h_mutant = unsafe { OpenMutexW(SYNCHRONIZE, FALSE, w_mutant_name.as_ptr() as *const u16) };
    let last_error = unsafe { GetLastError() };
    
    if h_mutant == NULL && last_error == ERROR_FILE_NOT_FOUND {
        return Ok(false);
    } else if h_mutant == NULL {
        return Err(last_error);
    }
    
    Ok(true)
}

pub fn is_any_unwanted_mutant_existent(unwanted_mutant_names: &HashSet<String>) -> Result<bool, DWORD> {
    for umn in unwanted_mutant_names {
        match is_mutant_existent(&umn) {
            Ok(true)  => return Ok(true),
            Ok(false) => (),
            Err(err)  => return Err(err),
        }
    }

    Ok(false)
}

pub fn is_symlink_existent(symlink_name: &String) -> Result<bool, DWORD> {
    let mut w_symlink_name = widestring::U16String::from_str(symlink_name);
    w_symlink_name.push_os_str("\x00");
    unsafe {
        let h_section = CreateFileW(
            w_symlink_name.as_ptr() as *const u16,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL as *mut _,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        if h_section == INVALID_HANDLE_VALUE {
            return Ok(false);
        }
    }

    Ok(true)
}

pub fn is_any_unwanted_symlink_existent(unwanted_symlink_names: &HashSet<String>) -> Result<bool, DWORD> {
    for sn in unwanted_symlink_names {
        match is_symlink_existent(sn) {
            Ok(true)  => return Ok(true),
            Ok(false) => (),
            Err(err)  => return Err(err),
        }
    }

    Ok(false)
}

pub fn is_debugged_peb() -> Result<bool, DWORD> {
    unsafe{
        Ok((*NtCurrentPeb()).BeingDebugged == 1)
    }
}

pub fn is_remotely_debugged() -> Result<bool, DWORD> {
    unsafe {
        let mut result: i32 = 0;
        if CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut result) > 0 {
            return Ok(result != 0);
        } else {
            return Err(GetLastError());
        }
    }
}

#[cfg(test)]
#[cfg(windows)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    #[test]
    fn test_system_process() {
        let mut p: HashSet<String> = HashSet::new();
        p.insert("[System Process]".to_string());

        assert_eq!(is_any_unwanted_process_running(&p), Ok(true))
    }

    #[test]
    fn test_fake_process() {
        let mut p: HashSet<String> = HashSet::new();
        // should be fake enough
        p.insert("m0q09fqucnqijx.exe".to_string());

        assert_eq!(is_any_unwanted_process_running(&p), Ok(false))
    }

    #[test]
    fn test_empty_set_processes() {
        let p: HashSet<String> = HashSet::new();
        
        assert_eq!(is_any_unwanted_process_running(&p), Ok(false));
    }

    #[test]
    fn test_ms_store_window() {
        let mut p: HashSet<String> = HashSet::new();
        p.insert("Microsoft Store".to_string());

        assert_eq!(is_any_unwanted_top_window_existent(&p), Ok(true));
    }

    #[test]
    fn test_mutant_dbwin() {
        assert_eq!(is_mutant_existent(&"DBWinMutex".to_string()), Ok(true));
    }

    #[test]
    fn test_mutant_dbwin2() {
        assert_eq!(is_mutant_existent(&"2DBWinMutex".to_string()), Ok(false));
    }

    #[test]
    #[ignore]
    fn test_symlink_sysmon() {
        assert_eq!(is_symlink_existent(&"\\\\.\\SysmonDrv".to_string()), Ok(true));
    }

    #[test]
    fn test_is_debugged_peb() {
        assert_eq!(is_debugged_peb(), Ok(false));
    }

    #[test]
    fn test_is_remotely_debugged() {
        assert_eq!(is_remotely_debugged(), Ok(false));
    }
}