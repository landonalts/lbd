// inject32.exe --inject <pid> <dll>   — WOW64 helper
#include <windows.h>
#include <cstdio>

static bool Inject(DWORD pid, const wchar_t* dll) {
    HANDLE p = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                           PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                           PROCESS_VM_READ, FALSE, pid);
    if (!p) return false;

    wchar_t full[MAX_PATH];
    if (!GetFullPathNameW(dll, MAX_PATH, full, nullptr)) { CloseHandle(p); return false; }
    SIZE_T n = (wcslen(full) + 1) * sizeof(wchar_t);

    void* mem = VirtualAllocEx(p, nullptr, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) { CloseHandle(p); return false; }
    if (!WriteProcessMemory(p, mem, full, n, nullptr)) {
        VirtualFreeEx(p, mem, 0, MEM_RELEASE); CloseHandle(p); return false;
    }

    auto load = (LPTHREAD_START_ROUTINE)
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    HANDLE th = CreateRemoteThread(p, nullptr, 0, load, mem, 0, nullptr);
    if (!th) { VirtualFreeEx(p, mem, 0, MEM_RELEASE); CloseHandle(p); return false; }

    WaitForSingleObject(th, 5000);
    DWORD ec = 0;
    GetExitCodeThread(th, &ec);
    CloseHandle(th);
    VirtualFreeEx(p, mem, 0, MEM_RELEASE);
    CloseHandle(p);
    return ec != 0;
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 4 || wcscmp(argv[1], L"--inject")) {
        wprintf(L"usage: inject32 --inject <pid> <dll>\n");
        return 2;
    }
    return Inject((DWORD)_wtoi(argv[2]), argv[3]) ? 0 : 1;
}
