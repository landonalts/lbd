// hide.cpp — payload injected into LockDownBrowser.exe
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <vector>
#include <string>
#include "MinHook.h"
#pragma comment(lib, "psapi.lib")

static HMODULE                   g_self = nullptr;
static std::vector<std::wstring> g_names;
static CRITICAL_SECTION          g_cs;
static bool                      g_ready = false;

static void LoadCfg() {
    EnterCriticalSection(&g_cs);
    if (g_ready) { LeaveCriticalSection(&g_cs); return; }
    g_ready = true;

    wchar_t path[MAX_PATH];
    GetModuleFileNameW(g_self, path, MAX_PATH);   // the DLL, not the host
    wchar_t* slash = wcsrchr(path, L'\\');
    if (!slash) { LeaveCriticalSection(&g_cs); return; }
    *(slash + 1) = 0;
    wcscat_s(path, L"hide.cfg");

    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) { LeaveCriticalSection(&g_cs); return; }

    char buf[8192]{};
    DWORD got = 0;
    ReadFile(f, buf, sizeof(buf) - 1, &got, nullptr);
    CloseHandle(f);

    std::string s(buf, got), line;
    auto flush = [&] {
        size_t a = line.find_first_not_of(" \t");
        if (a != std::string::npos && line[a] != '#')
            g_names.emplace_back(line.begin() + a, line.end());
        line.clear();
    };
    for (char c : s) {
        if (c == '\n' || c == '\r') flush();
        else line += c;
    }
    if (!line.empty()) flush();
    LeaveCriticalSection(&g_cs);
}

static bool Hidden(const wchar_t* img) {
    if (!g_ready) LoadCfg();
    for (const auto& n : g_names)
        if (!_wcsicmp(n.c_str(), img)) return true;
    return false;
}

static bool HiddenUS(const UNICODE_STRING& us) {
    if (!us.Buffer || !us.Length) return false;
    std::wstring w(us.Buffer, us.Length / sizeof(wchar_t));
    return Hidden(w.c_str());
}

typedef NTSTATUS (NTAPI *pNtQSI)(ULONG, PVOID, ULONG, PULONG);
static pNtQSI oNtQSI = nullptr;

static NTSTATUS NTAPI hNtQSI(ULONG cls, PVOID buf, ULONG len, PULONG ret) {
    NTSTATUS st = oNtQSI(cls, buf, len, ret);
    if (cls != SystemProcessInformation || !NT_SUCCESS(st) || !buf) return st;

    BYTE* base = (BYTE*)buf;
    SYSTEM_PROCESS_INFORMATION* prev = nullptr;
    for (;;) {
        auto* e = (SYSTEM_PROCESS_INFORMATION*)base;
        ULONG off = e->NextEntryOffset;

        if (HiddenUS(e->ImageName)) {
            if (prev) prev->NextEntryOffset += off;
            else {
                if (!off) return st;
                memmove(base, base + off, len - off);
                continue;
            }
        } else prev = e;

        if (!off) break;
        base += off;
    }
    return st;
}

typedef BOOL (WINAPI *pNext32)(HANDLE, LPPROCESSENTRY32W);
static pNext32 oNext32 = nullptr;

static BOOL WINAPI hNext32(HANDLE s, LPPROCESSENTRY32W pe) {
    for (;;) {
        if (!oNext32(s, pe)) return FALSE;
        if (!Hidden(pe->szExeFile)) return TRUE;
    }
}

typedef BOOL (WINAPI *pEnumPs)(DWORD*, DWORD, DWORD*);
static pEnumPs oEnumPs = nullptr;

static BOOL WINAPI hEnumPs(DWORD* ids, DWORD cb, DWORD* needed) {
    if (!oEnumPs(ids, cb, needed)) return FALSE;
    DWORD n = *needed / sizeof(DWORD), out = 0;
    for (DWORD i = 0; i < n; ++i) {
        HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ids[i]);
        if (!p) { ids[out++] = ids[i]; continue; }
        wchar_t img[MAX_PATH]; DWORD sz = MAX_PATH;
        QueryFullProcessImageNameW(p, 0, img, &sz);
        CloseHandle(p);
        const wchar_t* leaf = wcsrchr(img, L'\\');
        if (!Hidden(leaf ? leaf + 1 : img)) ids[out++] = ids[i];
    }
    *needed = out * sizeof(DWORD);
    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE mod, DWORD why, LPVOID) {
    if (why != DLL_PROCESS_ATTACH) return TRUE;
    g_self = mod;
    InitializeCriticalSection(&g_cs);
    LoadCfg();
    if (MH_Initialize() != MH_OK) return TRUE;
    MH_CreateHookApi(L"ntdll.dll", "NtQuerySystemInformation", hNtQSI, (void**)&oNtQSI);
    MH_CreateHookApi(L"kernel32.dll", "Process32NextW", hNext32, (void**)&oNext32);
    MH_CreateHookApi(L"kernel32.dll", "K32EnumProcesses", hEnumPs, (void**)&oEnumPs);
    MH_EnableHook(MH_ALL_HOOKS);
    return TRUE;
}
