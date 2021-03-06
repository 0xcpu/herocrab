extern crate widestring;
extern crate winapi;
extern crate ntapi;

use std::collections::{HashSet, HashMap};
use std::mem;

use winapi::shared::{
    minwindef::DWORD, minwindef::FALSE, minwindef::LPARAM, minwindef::MAX_PATH,
    minwindef::TRUE, ntdef::HANDLE, ntdef::NTSTATUS, ntdef::{NULL, OBJECT_ATTRIBUTES},
    ntstatus::STATUS_GUARD_PAGE_VIOLATION, ntstatus::STATUS_PORT_NOT_SET, ntstatus::STATUS_SUCCESS,
    windef::HWND, winerror::ERROR_FILE_NOT_FOUND
};
use winapi::um::winnt::{
    SYNCHRONIZE, GENERIC_READ, GENERIC_WRITE, FILE_SHARE_WRITE, FILE_SHARE_READ, FILE_ATTRIBUTE_NORMAL,
    CONTEXT, CONTEXT_DEBUG_REGISTERS, PEXCEPTION_POINTERS, MEM_COMMIT, MEM_RESERVE, MEM_RELEASE,
    PAGE_GUARD, PAGE_EXECUTE_READWRITE
};
use winapi::um::winnt::{RtlFillMemory};
use winapi::um::errhandlingapi::{GetLastError, AddVectoredExceptionHandler, RemoveVectoredExceptionHandler};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};
use winapi::um::winuser::{EnumWindows, GetWindowTextW, GetWindowTextLengthW};
use winapi::um::synchapi::OpenMutexW;
use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
use winapi::um::debugapi::CheckRemoteDebuggerPresent;
use winapi::um::processthreadsapi::{GetCurrentProcess, GetThreadContext, GetCurrentThread};
use winapi::um::minwinbase::EXCEPTION_BREAKPOINT;
use winapi::um::sysinfoapi::{GetSystemInfo, SYSTEM_INFO};
use winapi::um::memoryapi::{VirtualAlloc, VirtualFree, VirtualProtect};
use winapi::vc::excpt::{EXCEPTION_CONTINUE_SEARCH, EXCEPTION_CONTINUE_EXECUTION};
use winapi::um::psapi::{GetModuleInformation, MODULEINFO};
use winapi::um::libloaderapi::{LoadLibraryW, GetProcAddress};

use ntapi::{
    ntdbg::{DEBUG_ALL_ACCESS, NtCreateDebugObject},
    ntpsapi::{
    NtCurrentPeb, NtQueryInformationProcess, NtSetInformationThread, NtQueryInformationThread,
    ProcessDebugFlags, ProcessDebugObjectHandle, ThreadHideFromDebugger
}};
use ntapi::ntexapi::{NtQuerySystemInformation, SystemKernelDebuggerInformation};
use ntapi::ntobapi::{POBJECT_TYPE_INFORMATION, ObjectTypeInformation, NtQueryObject};

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
    
    if h_mutant.is_null() && last_error == ERROR_FILE_NOT_FOUND {
        return Ok(false);
    } else if h_mutant.is_null() {
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

extern "C" {
    fn c_is_debugged_invalid_handle() -> i32;
}

pub fn is_debugged_invalid_handle() -> Result<bool, DWORD> {
    match unsafe { c_is_debugged_invalid_handle() } {
        0 => Ok(false),
        _ => Ok(true)
    }
}

pub fn is_debugged_hw_bp() -> Result<bool, DWORD> {
    let mut ctx = unsafe { mem::zeroed::<CONTEXT>() };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if unsafe { GetThreadContext(GetCurrentThread(), &mut ctx) } == TRUE {
        if ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0 {
            return Ok(true);
        }
    } else {
        return unsafe { Err(GetLastError()) };
    }

    Ok(false)
}

static mut INT_2D_RESULT: bool = true;

unsafe extern "system" fn veh_handler_int2d(exception_info: PEXCEPTION_POINTERS) -> i32 {
    INT_2D_RESULT = false;

    if (*(*exception_info).ExceptionRecord).ExceptionCode == EXCEPTION_BREAKPOINT {
        #[cfg(target_arch = "x86_64")]
        {
            (*(*exception_info).ContextRecord).Rip += 1;
        }
        #[cfg(target_arch = "x86")]
        {
            (*(*exception_info).ContextRecord).Eip += 1;
        }

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    EXCEPTION_CONTINUE_SEARCH
}

pub fn is_debugged_int_2d() -> Result<bool, DWORD> {
    unsafe { INT_2D_RESULT = true; }

    let handle = unsafe { AddVectoredExceptionHandler(1, Some(veh_handler_int2d)) };
    if handle.is_null() {
        return unsafe { Err(GetLastError()) };
    }

    unsafe {
        asm!(
            "int   2dh",
            "nop"
        );

        RemoveVectoredExceptionHandler(handle);

        Ok(INT_2D_RESULT)
    }
}

static mut INT_3_RESULT: bool = true;

unsafe extern "system" fn veh_handler_int3(exception_info: PEXCEPTION_POINTERS) -> i32 {
    INT_3_RESULT = false;

    if (*(*exception_info).ExceptionRecord).ExceptionCode == EXCEPTION_BREAKPOINT {
        #[cfg(target_arch = "x86_64")]
        {
            (*(*exception_info).ContextRecord).Rip += 1;
        }
        #[cfg(target_arch = "x86")]
        {
            (*(*exception_info).ContextRecord).Eip += 1;
        }

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    EXCEPTION_CONTINUE_SEARCH
}

pub fn is_debugged_int_3() -> Result<bool, DWORD> {
    unsafe { INT_3_RESULT = true; }

    let handle = unsafe { AddVectoredExceptionHandler(1, Some(veh_handler_int3)) };
    if handle.is_null() {
        return unsafe { Err(GetLastError()) };
    }

    unsafe {
        asm!(
            "int   3h",
            "nop"
        );

        RemoveVectoredExceptionHandler(handle);

        Ok(INT_3_RESULT)
    }
}

pub fn is_debugged_global_flag() -> Result<bool, DWORD> {
    unsafe {
        Ok(((*NtCurrentPeb()).NtGlobalFlag & 0x00000070) != 0)
    }
}

static mut GUARD_PAGE_RESULT: bool = true;

unsafe extern "system" fn veh_handler_guard_page(exception_info: PEXCEPTION_POINTERS) -> i32 {
    GUARD_PAGE_RESULT = false;

    if (*(*exception_info).ExceptionRecord).ExceptionCode == STATUS_GUARD_PAGE_VIOLATION as u32 {
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    EXCEPTION_CONTINUE_SEARCH
}

pub fn is_debugged_guard_page() -> Result<bool, DWORD> {
    let mut system_info = unsafe { mem::zeroed::<SYSTEM_INFO>() };

    unsafe { GUARD_PAGE_RESULT = true; }

    let handle = unsafe { AddVectoredExceptionHandler(1, Some(veh_handler_guard_page)) };
    if handle.is_null() {
        return unsafe { Err(GetLastError()) };
    }

    unsafe { GetSystemInfo(&mut system_info) };

    let mem = unsafe { VirtualAlloc(
                                    NULL,
                                    system_info.dwPageSize as usize,
                                    MEM_COMMIT | MEM_RESERVE,
                                    PAGE_EXECUTE_READWRITE
                                    ) };
    if !mem.is_null() {
        unsafe { RtlFillMemory(mem, 1, 0xc3); }

        let mut old_prot = 0;
        if unsafe { VirtualProtect(
                                    mem,
                                    system_info.dwPageSize as usize,
                                    PAGE_EXECUTE_READWRITE | PAGE_GUARD, &mut old_prot
                                    ) } != 0 {
                                    let ptr = mem as *const ();
                                    let func = unsafe { std::mem::transmute::<*const (), extern "system" fn() -> ()>(ptr) };
                                    (func)();
        } else {
            unsafe {
                VirtualFree(mem, 0, MEM_RELEASE);
                RemoveVectoredExceptionHandler(handle);

                return Err(GetLastError());
            }
        }
    } else {
        unsafe {
            VirtualFree(mem, 0, MEM_RELEASE);
            RemoveVectoredExceptionHandler(handle);

            return Err(GetLastError());
        }
    }

    unsafe {
        VirtualFree(mem, 0, MEM_RELEASE);
        RemoveVectoredExceptionHandler(handle);

        Ok(GUARD_PAGE_RESULT)
    }
}

pub fn is_any_api_hooked(module_name: &mut String, module_apis: &Vec<String>) -> Result<bool, DWORD> {
    let mut module_info = unsafe { mem::zeroed::<MODULEINFO>() };
    let mut w_module_name = widestring::U16String::from_str(module_name);
    w_module_name.push_os_str(".dll\x00");

    let h_module = unsafe { LoadLibraryW(w_module_name.as_ptr() as *const u16) };
    if h_module.is_null() {
        unsafe { return Err(GetLastError()); }
    }

    unsafe {
        if GetModuleInformation(
            GetCurrentProcess(),
            h_module,
            &mut module_info,
            std::mem::size_of::<MODULEINFO>() as u32) == FALSE {
                return Err(GetLastError());
            }
    }

    let base = module_info.lpBaseOfDll as usize;
    let end  = module_info.lpBaseOfDll as usize + module_info.SizeOfImage as usize;
    for api in module_apis {
        let p = unsafe { GetProcAddress(h_module, api.as_str().as_ptr() as *const i8) };
        if !p.is_null() {
            let ptr  = p as usize;
            if ptr < base || ptr >= end {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

pub fn is_any_module_hooked(mod_apis: &HashMap<String, Vec<String>>) -> Result<bool, DWORD> {
    for (module_name, module_apis) in mod_apis {
        match is_any_api_hooked(&mut module_name.clone(), &module_apis) {
            Ok(true) => return Ok(true),
            Err(err) => return Err(err),
            _        => (),
        }
    }

    Ok(false)
}

pub fn is_debugged_debug_flags() -> Result<bool, DWORD> {
    let mut dw_no_debug: DWORD = 0;
    let nt_status: NTSTATUS = unsafe {
        NtQueryInformationProcess(
            GetCurrentProcess(),
            ProcessDebugFlags,
            &mut dw_no_debug as *mut _ as *mut _,
            mem::size_of::<DWORD>() as u32,
            NULL as *mut _
        )
    };

    if nt_status == STATUS_SUCCESS && dw_no_debug == 0 {
        Ok(true)
    } else {
        Ok(false)
    }
}

pub fn is_debugged_debug_port() -> Result<bool, DWORD> {
    let mut h_debug_port: HANDLE = NULL;
    let nt_status: NTSTATUS = unsafe {
        NtQueryInformationProcess(
            GetCurrentProcess(),
            ProcessDebugObjectHandle,
            &mut h_debug_port as *mut _ as *mut _,
            #[cfg(target_arch = "x86_64")]
            {
                (mem::size_of::<DWORD>() * 2) as u32
            },
            #[cfg(target_arch = "x86")]
            {
                mem::size_of::<DWORD>() as u32
            },
            NULL as *mut _
        )
    };

    if nt_status != STATUS_PORT_NOT_SET {
        Ok(true)
    } else if !h_debug_port.is_null() {
        Ok(true)
    } else {
        Ok(false)
    }
}

// Based on WudfIsKernelDebuggerPresent in WUDFPlatform.dll
pub fn is_kernel_debugger_present() -> Result<bool, DWORD> {
    let mut no_kernel_debug: i16 = 0;
    let nt_status: NTSTATUS = unsafe {
          NtQuerySystemInformation(
              SystemKernelDebuggerInformation, 
              &mut no_kernel_debug as *mut _ as *mut _,
              mem::size_of::<i16>() as u32,
              NULL as *mut _)
    };

    if nt_status == STATUS_SUCCESS {
        if no_kernel_debug != 0x1 {
            Ok(false)
        } else {
            Ok(true)
        }
    } else {
        Ok(false)
    }
}

pub fn does_thread_hide_fail() -> Result<bool, DWORD> {
    let nt_status: NTSTATUS = unsafe {
        NtSetInformationThread(
            GetCurrentThread(),
            ThreadHideFromDebugger,
            NULL as *mut _,
            0)
    };

    if nt_status == STATUS_SUCCESS {
        let mut is_thread_hidden = false;
        let nt_status: NTSTATUS = unsafe {
            NtQueryInformationThread(
                GetCurrentThread(),
                ThreadHideFromDebugger,
                &mut is_thread_hidden as *mut _ as *mut _,
                mem::size_of::<bool>() as u32,
                NULL as *mut _)
        };

        if nt_status == STATUS_SUCCESS {
            match is_thread_hidden {
                true => return Ok(false),
                false => return Ok(true),
            }
        }

        unsafe {
            Err(GetLastError())
        }
    } else {
        Ok(true)
    }
}

pub fn is_objinfo_numobj_hooked() -> Result<bool, DWORD> {
    let mut h_debug_object: HANDLE = NULL;
    let mut obj_attrib = unsafe { mem::zeroed::<OBJECT_ATTRIBUTES>() };
    let obj_info: POBJECT_TYPE_INFORMATION = vec![0; 4096].as_mut_ptr() as *mut _;

    let nt_status: NTSTATUS = unsafe {
        NtCreateDebugObject(&mut h_debug_object as *mut _, DEBUG_ALL_ACCESS, &mut obj_attrib, 0)
    };
    if nt_status == STATUS_SUCCESS {
        let nt_status: NTSTATUS = unsafe {
            CloseHandle(h_debug_object);

            NtQueryObject(
                h_debug_object, 
                ObjectTypeInformation, 
                obj_info as *mut _, 
                4096, 
                0 as *mut _)
        };

        unsafe {
            dbg!((*obj_info).TotalNumberOfObjects);
            if nt_status == STATUS_SUCCESS && (*obj_info).TotalNumberOfObjects == 0 {
                return Ok(true);
            }
        }
    }

    Ok(false)
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

    #[test]
    fn test_is_debugged_invalid_handle() {
        assert_eq!(is_debugged_invalid_handle(), Ok(false));
    }

    #[test]
    fn test_is_debugged_hw_bp() {
        assert_eq!(is_debugged_hw_bp(), Ok(false));
    }

    #[test]
    fn test_is_debugged_int_2d() {
        assert_eq!(is_debugged_int_2d(), Ok(false));
    }

    #[test]
    fn test_is_debugged_int_3() {
        assert_eq!(is_debugged_int_3(), Ok(false));
    }

    #[test]
    fn test_is_debugged_global_flag() {
        assert_eq!(is_debugged_global_flag(), Ok(false));
    }

    #[test]
    fn test_is_debugged_guard_page() {
        assert_eq!(is_debugged_guard_page(), Ok(false));
    }

    #[test]
    fn test_is_any_module_hooked() {
        let mut hash_map = HashMap::new();
        hash_map.insert("ntdll".to_string(), vec!["A_SHAFinal".to_string()]);
        assert_eq!(is_any_module_hooked(&hash_map), Ok(false));
    }

    #[test]
    fn test_is_debugged_debug_flags() {
        assert_eq!(is_debugged_debug_flags(), Ok(false));
    }

    #[test]
    fn test_is_debugged_debug_port() {
        assert_eq!(is_debugged_debug_port(), Ok(false));
    }

    #[test]
    fn test_is_kernel_debugger_present() {
        assert_eq!(is_kernel_debugger_present(), Ok(false));
    }

    #[test]
    fn test_thread_hide_failed() {
        assert_eq!(does_thread_hide_fail(), Ok(false));
    }

    #[test]
    fn test_is_objinfo_numobj_hooked() {
        assert_eq!(is_objinfo_numobj_hooked(), Ok(false));
    }
}