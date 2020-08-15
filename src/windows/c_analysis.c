#include <Windows.h>

int c_is_debugged_invalid_handle() {
    // no error checking!
    HMODULE hLib = LoadLibrary("ntdll.dll");
    FARPROC pNtClose = GetProcAddress(hLib, "NtClose");

    __try {
        NtClose((HANDLE)0xcafebabe);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return TRUE;
    }

    return FALSE;
}