// ldbwatch.cpp — watcher, injector dispatch, input hook
#define WIN32_LEAN_AND_MEAN
#define UNICODE
#include <windows.h>
#include <tlhelp32.h>
#include <dwmapi.h>
#include <vector>
#include <string>
#include <cstdio>
#include <cstdarg>

static const wchar_t* TARGET = L"LockDownBrowser.exe";
static HHOOK  g_hook = nullptr;
static HWND   g_exam = nullptr;
static HWND   g_peek = nullptr;
static DWORD  g_pid  = 0;
static int    g_idx  = -1;
static volatile bool g_quit = false;
static std::vector<HWND> g_others;
static CRITICAL_SECTION  g_cs;

static void Log(const wchar_t* f, ...) {
    EnterCriticalSection(&g_cs);
    SYSTEMTIME t; GetLocalTime(&t);
    wprintf(L"  %02d:%02d:%02d  ", t.wHour, t.wMinute, t.wSecond);
    va_list a; va_start(a, f); vwprintf(f, a); va_end(a);
    wprintf(L"\n");
    LeaveCriticalSection(&g_cs);
}

static DWORD FindTarget() {
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (s == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{ sizeof(pe) };
    DWORD found = 0;
    if (Process32FirstW(s, &pe)) do {
        if (!_wcsicmp(pe.szExeFile, TARGET)) { found = pe.th32ProcessID; break; }
    } while (Process32NextW(s, &pe));
    CloseHandle(s);
    return found;
}

static bool TargetIsWow64(DWORD pid) {
    HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!p) return false;
    BOOL w = FALSE;
    IsWow64Process(p, &w);
    CloseHandle(p);
    return w != FALSE;
}

static bool InjectDirect(DWORD pid, const wchar_t* dll) {
    HANDLE p = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                           PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                           PROCESS_VM_READ, FALSE, pid);
    if (!p) { Log(L"OpenProcess failed (%lu) - elevated?", GetLastError()); return false; }

    wchar_t full[MAX_PATH];
    if (!GetFullPathNameW(dll, MAX_PATH, full, nullptr)) { CloseHandle(p); return false; }
    SIZE_T n = (wcslen(full) + 1) * sizeof(wchar_t);

    void* mem = VirtualAllocEx(p, nullptr, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) { Log(L"VirtualAllocEx failed (%lu)", GetLastError()); CloseHandle(p); return false; }
    if (!WriteProcessMemory(p, mem, full, n, nullptr)) {
        Log(L"WriteProcessMemory failed (%lu)", GetLastError());
        VirtualFreeEx(p, mem, 0, MEM_RELEASE); CloseHandle(p); return false;
    }

    auto load = (LPTHREAD_START_ROUTINE)
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    HANDLE th = CreateRemoteThread(p, nullptr, 0, load, mem, 0, nullptr);
    if (!th) {
        Log(L"CreateRemoteThread failed (%lu)", GetLastError());
        VirtualFreeEx(p, mem, 0, MEM_RELEASE); CloseHandle(p); return false;
    }
    WaitForSingleObject(th, 5000);
    DWORD ec = 0; GetExitCodeThread(th, &ec);
    CloseHandle(th); VirtualFreeEx(p, mem, 0, MEM_RELEASE); CloseHandle(p);
    if (!ec) { Log(L"LoadLibraryW returned null in target"); return false; }
    return true;
}

static bool InjectViaHelper(DWORD pid) {
    wchar_t exe[MAX_PATH], dll[MAX_PATH], cmd[MAX_PATH * 3];
    GetFullPathNameW(L"inject32.exe", MAX_PATH, exe, nullptr);
    GetFullPathNameW(L"hide32.dll", MAX_PATH, dll, nullptr);
    swprintf_s(cmd, L"\"%s\" --inject %lu \"%s\"", exe, pid, dll);

    STARTUPINFOW si{ sizeof(si) };
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        Log(L"cannot start inject32.exe (%lu)", GetLastError());
        return false;
    }
    WaitForSingleObject(pi.hProcess, 5000);
    DWORD ec = 1; GetExitCodeProcess(pi.hProcess, &ec);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return ec == 0;
}

static bool Inject(DWORD pid) {
    if (TargetIsWow64(pid)) {
        Log(L"target is 32-bit, using helper");
        return InjectViaHelper(pid);
    }
    return InjectDirect(pid, L"hide64.dll");
}

static DWORD WINAPI Watch(LPVOID) {
    DWORD last = 0;
    while (!g_quit) {
        DWORD pid = FindTarget();
        if (pid && pid != last) {
            last = pid;
            Log(L"detected %s (pid %lu)", TARGET, pid);
            Sleep(40);
            Log(Inject(pid) ? L"payload loaded" : L"injection failed - window control only");
            g_pid = pid; g_exam = nullptr;
        } else if (!pid && last) {
            Log(L"target exited, re-arming");
            last = 0; g_pid = 0; g_exam = nullptr; g_idx = -1;
        }
        Sleep(10);
    }
    return 0;
}

static BOOL CALLBACK FindExam(HWND h, LPARAM) {
    if (!g_pid || !IsWindowVisible(h)) return TRUE;
    DWORD pid = 0; GetWindowThreadProcessId(h, &pid);
    if (pid == g_pid) { g_exam = h; return FALSE; }
    return TRUE;
}

static BOOL CALLBACK Collect(HWND h, LPARAM) {
    if (h == g_exam || !IsWindowVisible(h) || GetWindow(h, GW_OWNER)) return TRUE;
    int cl = 0; DwmGetWindowAttribute(h, DWMWA_CLOAKED, &cl, sizeof(cl));
    if (cl) return TRUE;
    if (GetWindowLongPtrW(h, GWL_EXSTYLE) & WS_EX_TOOLWINDOW) return TRUE;
    wchar_t t[256]{}; if (!GetWindowTextW(h, t, 256)) return TRUE;
    g_others.push_back(h);
    return TRUE;
}

static void Cycle() {
    if (!g_exam) { EnumWindows(FindExam, 0); if (!g_exam) return; }
    g_others.clear();
    EnumWindows(Collect, 0);
    if (g_others.empty()) return;
    g_idx = (g_idx + 1) % (int)g_others.size();
    HWND t = g_others[g_idx];
    SetWindowPos(g_exam, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    SetWindowPos(t, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
    SetForegroundWindow(t);
    wchar_t b[256]{}; GetWindowTextW(t, b, 256);
    Log(L"-> %s", b);
}

static void ToExam() {
    if (!g_exam) return;
    if (g_peek) {
        SetWindowPos(g_peek, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        g_peek = nullptr;
    }
    SetWindowPos(g_exam, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
    SetForegroundWindow(g_exam);
}

static void Peek() {
    if (!g_exam || g_others.empty()) return;
    HWND t = g_others[g_idx < 0 ? 0 : g_idx];
    LONG_PTR ex = GetWindowLongPtrW(t, GWL_EXSTYLE);
    SetWindowLongPtrW(t, GWL_EXSTYLE, (ex | WS_EX_NOACTIVATE) & ~WS_EX_APPWINDOW);
    SetWindowDisplayAffinity(t, WDA_EXCLUDEFROMCAPTURE);
    SetWindowPos(t, HWND_TOPMOST, 0, 0, 0, 0,
                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
    g_peek = t;
    SetWindowPos(g_exam, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
    SetForegroundWindow(g_exam);
    Log(L"peek: overlay floats, exam keeps focus");
}

static void ToggleConsole() {
    static bool shown = true;
    shown = !shown;
    ShowWindow(GetConsoleWindow(), shown ? SW_SHOW : SW_HIDE);
}

static LRESULT CALLBACK LLK(int n, WPARAM w, LPARAM l) {
    if (n == HC_ACTION) {
        auto* k = (KBDLLHOOKSTRUCT*)l;
        bool down = (w == WM_KEYDOWN || w == WM_SYSKEYDOWN);
        bool alt = (k->flags & LLKHF_ALTDOWN) || (GetAsyncKeyState(VK_MENU) & 0x8000);
        bool ctrl = (GetAsyncKeyState(VK_CONTROL) & 0x8000);

        if (alt && k->vkCode == VK_TAB) { if (down) Cycle(); return 1; }
        if (ctrl && k->vkCode == VK_ESCAPE) { if (down) Cycle(); return 1; }
        if (ctrl && alt) {
            switch (k->vkCode) {
            case VK_SPACE:   if (down) Peek(); return 1;
            case VK_RETURN:  if (down) ToExam(); return 1;
            case VK_H:       if (down) ToggleConsole(); return 1;
            case VK_Q:       if (down) g_quit = true; return 1;
            }
        }
        if (k->vkCode == VK_LWIN || k->vkCode == VK_RWIN) {
            if (down) Cycle();
            return 1;
        }
    }
    return CallNextHookEx(g_hook, n, w, l);
}

int main() {
    InitializeCriticalSection(&g_cs);
    SetConsoleTitleW(L"ldbwatch");

    wprintf(L"\n  ldbwatch\n  --------\n");
    wprintf(L"  Alt+Tab / Win / Ctrl+Esc   cycle windows\n");
    wprintf(L"  Ctrl+Alt+Space             peek (exam keeps focus)\n");
    wprintf(L"  Ctrl+Alt+Enter             back to exam\n");
    wprintf(L"  Ctrl+Alt+H                 hide console\n");
    wprintf(L"  Ctrl+Alt+Q                 quit\n\n");

    HANDLE tok = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        TOKEN_ELEVATION e{}; DWORD sz = sizeof(e);
        GetTokenInformation(tok, TokenElevation, &e, sz, &sz);
        if (!e.TokenIsElevated)
            wprintf(L"  [!] not elevated - injection will fail\n\n");
        CloseHandle(tok);
    }

    g_hook = SetWindowsHookExW(WH_KEYBOARD_LL, LLK, GetModuleHandleW(nullptr), 0);
    if (!g_hook) { wprintf(L"  hook failed (%lu)\n", GetLastError()); return 1; }

    CreateThread(nullptr, 0, Watch, nullptr, 0, nullptr);
    wprintf(L"  watching for %s ...\n\n", TARGET);

    MSG m;
    while (!g_quit && GetMessageW(&m, nullptr, 0, 0)) {
        TranslateMessage(&m); DispatchMessageW(&m);
    }
    UnhookWindowsHookEx(g_hook);
    wprintf(L"\n  stopped.\n");
    return 0;
}
