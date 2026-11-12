/*
 * installer.c - AirMon 安装向导 (纯 Win32, 不依赖任何外部打包工具)
 *
 * 为什么自己写: 本机没有 WiX / Inno Setup / NSIS, 也没有网络装不了。
 * 所以用系统自带能力(CreateWindow + IShellLink + 注册表)做一个单页安装器,
 * 把 airmon.exe / viewer.html 用 RCDATA 资源嵌在安装器自身里, 双击即可安装。
 *
 * 用法:
 *   AirMon-Setup.exe               -> 安装向导
 *   AirMon-Setup.exe /uninstall    -> 卸载(由安装目录里的 uninstall.exe 调用)
 *   AirMon-Setup.exe /S            -> 静默安装到默认目录(可选, 供脚本用)
 *
 * 安装位置: 默认 %LOCALAPPDATA%\Programs\AirMon
 *   —— 用用户目录而不是 Program Files, 是因为 airmon 会把 airmon.db /
 *      airmon.ini / airmon.log 写在 exe 同目录, Program Files 下没有写权限,
 *      数据库就存不下来。当然用户仍可浏览选任意目录(装到只读目录会提示)。
 *
 * 卸载信息写到 HKCU 的 Uninstall 键, 所以不需要管理员权限,
 * 也能在「设置 → 应用」/「程序和功能」里看到并卸载。
 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>
#include <shellapi.h>
#include <objbase.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#define APP_NAME     L"AirMon 空气质量监测"
#define APP_SHORT    L"AirMon"
#define APP_VERSION  L"1.0.0"
#define APP_PUBLISHER L"AirMon"
#define UNINST_KEY   L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AirMon"
#define RUN_KEY      L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#define UNINST_NAME  L"uninstall.exe"

/* ---------------- 控件 ID ---------------- */
#define ID_PATH     1001
#define ID_BROWSE   1002
#define ID_AUTORUN  1003
#define ID_DESKTOP  1004
#define ID_STARTMENU 1005
#define ID_INSTALL  1006
#define ID_CANCEL   1007
#define ID_STATUS   1008
#define ID_LAUNCH   1009

static HWND g_hwnd, g_path, g_status, g_autorun, g_desktop, g_startmenu, g_launch;
static HFONT g_font;
static BOOL  g_busy = FALSE;
static WCHAR g_logpath[MAX_PATH] = {0};

static void join_path(WCHAR* out, size_t cap, const WCHAR* dir, const WCHAR* name);

/* 安装日志: 静默安装(/S)时没有界面, 失败原因只能靠它看。
 * 写在 %TEMP%\AirMon-Setup.log, 正常安装也写, 方便排查。 */
static void ilog(const WCHAR* fmt, ...)
{
    WCHAR buf[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf(buf, ARRAYSIZE(buf) - 1, fmt, ap);
    va_end(ap);
    buf[ARRAYSIZE(buf) - 1] = 0;

    if (!g_logpath[0]) {
        WCHAR tmp[MAX_PATH];
        GetTempPathW(MAX_PATH, tmp);
        join_path(g_logpath, MAX_PATH, tmp, L"AirMon-Setup.log");
    }

    HANDLE f = CreateFileW(g_logpath, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return;

    SYSTEMTIME st;
    GetLocalTime(&st);

    /* 注意: 不要用 _snprintf("%ls") —— MinGW 的窄字符格式化对 %ls 行为不可靠,
     * 之前就是它导致日志文件被创建但内容为空。这里手工转成 UTF-8。 */
    WCHAR wline[1200];
    _snwprintf(wline, ARRAYSIZE(wline) - 1,
               L"[%04d-%02d-%02d %02d:%02d:%02d] %s\r\n",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, buf);
    wline[ARRAYSIZE(wline) - 1] = 0;

    char line[4096];
    int n = WideCharToMultiByte(CP_UTF8, 0, wline, -1, line, sizeof line - 1, NULL, NULL);
    if (n > 0) {
        DWORD w = 0;
        WriteFile(f, line, (DWORD)(n - 1), &w, NULL);   /* n 含结尾 0 */
    }
    CloseHandle(f);
}

/* ---------------- 工具 ---------------- */
static void join_path(WCHAR* out, size_t cap, const WCHAR* dir, const WCHAR* name)
{
    size_t n = wcslen(dir);
    int need_sep = (n > 0 && dir[n-1] != L'\\');
    _snwprintf(out, cap, L"%s%s%s", dir, need_sep ? L"\\" : L"", name);
    out[cap-1] = 0;
}

static void default_dir(WCHAR* out, size_t cap)
{
    WCHAR base[MAX_PATH] = {0};
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, base))) {
        GetCurrentDirectoryW(MAX_PATH, base);
    }
    _snwprintf(out, cap, L"%s\\Programs\\%s", base, APP_SHORT);
    out[cap-1] = 0;
}

static void set_status(const WCHAR* fmt, ...)
{
    WCHAR buf[512];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf(buf, ARRAYSIZE(buf) - 1, fmt, ap);
    va_end(ap);
    buf[ARRAYSIZE(buf) - 1] = 0;
    SetWindowTextW(g_status, buf);
    UpdateWindow(g_status);
}

static int dir_writable(const WCHAR* dir)
{
    WCHAR probe[MAX_PATH];
    join_path(probe, MAX_PATH, dir, L".airmon_write_test");
    HANDLE h = CreateFileW(probe, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    CloseHandle(h);
    return 1;
}

static int ensure_dir(const WCHAR* dir)
{
    if (CreateDirectoryW(dir, NULL)) return 1;
    if (GetLastError() == ERROR_ALREADY_EXISTS) return 1;

    /* 逐级创建。注意不要从 tmp+3 开始瞎走 —— "C:\Users\..." 会去创建 "C:",
     * 那必然 ERROR_ACCESS_DENIED, 于是明明可写的目录也被判成不可写。
     * 正确做法: 逐段尝试, 忽略"已存在", 最后再判目标目录是否真的在。 */
    {
        WCHAR tmp[MAX_PATH];
        lstrcpynW(tmp, dir, MAX_PATH);

        for (WCHAR* p = tmp; *p; p++) {
            if (*p == L'\\' && p > tmp + 1) {
                WCHAR save = *p;
                *p = 0;
                CreateDirectoryW(tmp, NULL);   /* 已存在也无所谓 */
                *p = save;
            }
        }
        CreateDirectoryW(tmp, NULL);
    }

    /* 以"目录是否真的存在"为准, 不要只看最后一次 CreateDirectory 的返回值 */
    DWORD a = GetFileAttributesW(dir);
    return (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY)) ? 1 : 0;
}

/* 从自身资源里取出 RCDATA 写到目标文件 */
static int extract_res(LPCWSTR name, const WCHAR* outfile)
{
    HRSRC   r = FindResourceW(NULL, name, RT_RCDATA);
    if (!r) return 0;
    HGLOBAL h = LoadResource(NULL, r);
    if (!h) return 0;
    DWORD   sz = SizeofResource(NULL, r);
    void*   p  = LockResource(h);
    if (!p || !sz) return 0;

    HANDLE f = CreateFileW(outfile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return 0;
    DWORD written = 0;
    BOOL ok = WriteFile(f, p, sz, &written, NULL);
    CloseHandle(f);
    return (ok && written == sz) ? 1 : 0;
}

/* 复制自身(当卸载程序用) */
static int copy_self(const WCHAR* outfile)
{
    WCHAR self[MAX_PATH];
    GetModuleFileNameW(NULL, self, MAX_PATH);
    if (lstrcmpiW(self, outfile) == 0) return 1;
    return CopyFileW(self, outfile, FALSE) ? 1 : 0;
}

/* ---------------- 快捷方式 ---------------- */
static int make_shortcut(const WCHAR* lnk, const WCHAR* target, const WCHAR* workdir,
                         const WCHAR* desc)
{
    IShellLinkW* sl = NULL;
    IPersistFile* pf = NULL;
    int ok = 0;

    if (FAILED(CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
                                &IID_IShellLinkW, (void**)&sl))) return 0;

    sl->lpVtbl->SetPath(sl, target);
    sl->lpVtbl->SetWorkingDirectory(sl, workdir);
    sl->lpVtbl->SetDescription(sl, desc);
    sl->lpVtbl->SetIconLocation(sl, target, 0);

    if (SUCCEEDED(sl->lpVtbl->QueryInterface(sl, &IID_IPersistFile, (void**)&pf))) {
        ok = SUCCEEDED(pf->lpVtbl->Save(pf, lnk, TRUE)) ? 1 : 0;
        pf->lpVtbl->Release(pf);
    }
    sl->lpVtbl->Release(sl);
    return ok;
}

/* 取某个 CSIDL 目录下的 lnk 路径 */
static int shortcut_path(int csidl, const WCHAR* name, WCHAR* out, size_t cap)
{
    WCHAR dir[MAX_PATH] = {0};
    if (FAILED(SHGetFolderPathW(NULL, csidl, NULL, 0, dir))) return 0;
    join_path(out, cap, dir, name);
    return 1;
}

/* ---------------- 注册表 ---------------- */
static int reg_set_str(HKEY root, const WCHAR* sub, const WCHAR* name, const WCHAR* val)
{
    HKEY k = NULL;
    int ok = 0;
    if (RegCreateKeyExW(root, sub, 0, NULL, 0, KEY_WRITE, NULL, &k, NULL) == ERROR_SUCCESS) {
        ok = (RegSetValueExW(k, name, 0, REG_SZ, (const BYTE*)val,
                             (DWORD)((wcslen(val) + 1) * sizeof(WCHAR))) == ERROR_SUCCESS) ? 1 : 0;
        RegCloseKey(k);
    }
    return ok;
}

static void reg_set_dword(HKEY root, const WCHAR* sub, const WCHAR* name, DWORD v)
{
    HKEY k = NULL;
    if (RegCreateKeyExW(root, sub, 0, NULL, 0, KEY_WRITE, NULL, &k, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(k, name, 0, REG_DWORD, (const BYTE*)&v, sizeof v);
        RegCloseKey(k);
    }
}

static void reg_del_value(HKEY root, const WCHAR* sub, const WCHAR* name)
{
    HKEY k = NULL;
    if (RegOpenKeyExW(root, sub, 0, KEY_SET_VALUE, &k) == ERROR_SUCCESS) {
        RegDeleteValueW(k, name);
        RegCloseKey(k);
    }
}

static void reg_del_tree(HKEY root, const WCHAR* sub)
{
    HKEY k = NULL;
    if (RegOpenKeyExW(root, sub, 0, KEY_READ | KEY_WRITE, &k) == ERROR_SUCCESS) {
        RegDeleteTreeW(k, NULL);
        RegCloseKey(k);
    }
    RegDeleteKeyW(root, sub);
}

/* ---------------- 安装 / 卸载 ---------------- */
static BOOL do_install(const WCHAR* dir, int autorun, int desktop, int startmenu, int launch)
{
    WCHAR exe[MAX_PATH], html[MAX_PATH], uninst[MAX_PATH];

    ilog(L"=== 开始安装 ===");
    ilog(L"目标目录: %s", dir);
    ilog(L"选项: 自启=%d 桌面=%d 开始菜单=%d 启动=%d", autorun, desktop, startmenu, launch);

    set_status(L"正在检查安装目录…");
    if (!ensure_dir(dir)) {
        ilog(L"失败: 无法创建目录 (GetLastError=%lu)", GetLastError());
        set_status(L"无法创建目录: %s", dir);
        return FALSE;
    }
    ilog(L"目录已就绪");
    if (!dir_writable(dir)) {
        ilog(L"失败: 目录不可写");
        set_status(L"目录不可写: %s\n请换一个目录(不要用 Program Files, 除非以管理员运行)", dir);
        return FALSE;
    }
    ilog(L"目录可写");

    join_path(exe, MAX_PATH, dir, L"airmon.exe");
    join_path(html, MAX_PATH, dir, L"viewer.html");
    join_path(uninst, MAX_PATH, dir, UNINST_NAME);

    set_status(L"正在释放 airmon.exe…");
    if (!extract_res(L"AIRMON_EXE", exe)) {
        ilog(L"失败: 释放 airmon.exe (GetLastError=%lu)", GetLastError());
        set_status(L"释放 airmon.exe 失败");
        return FALSE;
    }
    ilog(L"已释放 airmon.exe");

    set_status(L"正在释放 viewer.html…");
    if (!extract_res(L"VIEWER_HTML", html)) {
        ilog(L"失败: 释放 viewer.html (GetLastError=%lu)", GetLastError());
        set_status(L"释放 viewer.html 失败");
        return FALSE;
    }
    ilog(L"已释放 viewer.html");

    set_status(L"正在写入卸载程序…");
    if (!copy_self(uninst)) {
        ilog(L"失败: 复制卸载程序 (GetLastError=%lu)", GetLastError());
        set_status(L"写入卸载程序失败");
        return FALSE;
    }
    ilog(L"已写入卸载程序");

    /* 桌面快捷方式 */
    if (desktop) {
        WCHAR lnk[MAX_PATH];
        set_status(L"正在创建桌面快捷方式…");
        if (shortcut_path(CSIDL_DESKTOPDIRECTORY, L"AirMon.lnk", lnk, MAX_PATH))
            ilog(make_shortcut(lnk, exe, dir, APP_NAME)
                 ? L"桌面快捷方式: 成功" : L"桌面快捷方式: 失败 (可能无权限写桌面)");
        else
            ilog(L"桌面快捷方式: 失败 (取不到桌面路径)");
    }

    /* 开始菜单快捷方式 */
    if (startmenu) {
        WCHAR lnk[MAX_PATH];
        WCHAR prog[MAX_PATH] = {0};
        set_status(L"正在创建开始菜单快捷方式…");
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROGRAMS, NULL, 0, prog))) {
            WCHAR folder[MAX_PATH];
            join_path(folder, MAX_PATH, prog, APP_SHORT);
            CreateDirectoryW(folder, NULL);
            join_path(lnk, MAX_PATH, folder, L"AirMon.lnk");
            ilog(make_shortcut(lnk, exe, dir, APP_NAME)
                 ? L"开始菜单快捷方式: 成功" : L"开始菜单快捷方式: 失败");
            /* 卸载快捷方式 */
            WCHAR lnk2[MAX_PATH];
            join_path(lnk2, MAX_PATH, folder, L"卸载 AirMon.lnk");
            make_shortcut(lnk2, uninst, dir, L"卸载 AirMon");
        } else {
            ilog(L"开始菜单快捷方式: 失败 (取不到开始菜单路径)");
        }
    }

    /* 开机自启 */
    set_status(L"正在写入启动项…");
    if (autorun) {
        WCHAR cmd[MAX_PATH + 8];
        _snwprintf(cmd, ARRAYSIZE(cmd), L"\"%s\"", exe);
        cmd[ARRAYSIZE(cmd)-1] = 0;
        ilog(reg_set_str(HKEY_CURRENT_USER, RUN_KEY, APP_SHORT, cmd)
             ? L"开机自启: 已写入 %s" : L"开机自启: 写入失败 (注册表不可写)", cmd);
    } else {
        reg_del_value(HKEY_CURRENT_USER, RUN_KEY, APP_SHORT);
        ilog(L"开机自启: 未启用");
    }

    /* 卸载信息(出现在「设置 → 应用」里) */
    set_status(L"正在注册卸载信息…");
    {
        WCHAR uninst_cmd[MAX_PATH + 32];
        _snwprintf(uninst_cmd, ARRAYSIZE(uninst_cmd), L"\"%s\" /uninstall", uninst);
        uninst_cmd[ARRAYSIZE(uninst_cmd)-1] = 0;

        int ok = 1;
        /* 注意用 &&= 的逻辑: 不要写 ok &= f(), 那是按位与,
         * 返回值非 0/1 时会得到错误结果。 */
        if (!reg_set_str(HKEY_CURRENT_USER, UNINST_KEY, L"DisplayName", APP_NAME)) ok = 0;
        reg_set_str(HKEY_CURRENT_USER, UNINST_KEY, L"DisplayVersion", APP_VERSION);
        reg_set_str(HKEY_CURRENT_USER, UNINST_KEY, L"Publisher", APP_PUBLISHER);
        reg_set_str(HKEY_CURRENT_USER, UNINST_KEY, L"InstallLocation", dir);
        reg_set_str(HKEY_CURRENT_USER, UNINST_KEY, L"UninstallString", uninst_cmd);
        reg_set_str(HKEY_CURRENT_USER, UNINST_KEY, L"DisplayIcon", exe);
        reg_set_dword(HKEY_CURRENT_USER, UNINST_KEY, L"NoModify", 1);
        reg_set_dword(HKEY_CURRENT_USER, UNINST_KEY, L"NoRepair", 1);
        ilog(ok ? L"卸载信息: 已注册" : L"卸载信息: 注册失败 (注册表不可写)");
    }

    set_status(L"安装完成");
    ilog(L"=== 安装完成 ===");
    ilog(L"程序文件: %s", dir);
    ilog(L"日志: %s", g_logpath);

    if (launch) {
        ShellExecuteW(NULL, L"open", exe, NULL, dir, SW_SHOWNORMAL);
    }
    return TRUE;
}

static void do_uninstall(const WCHAR* dir)
{
    WCHAR exe[MAX_PATH], html[MAX_PATH], uninst[MAX_PATH], lnk[MAX_PATH], prog[MAX_PATH];

    /* 1) 先杀掉正在运行的 airmon, 否则删不掉 exe */
    {
        WCHAR cmd[MAX_PATH + 64];
        _snwprintf(cmd, ARRAYSIZE(cmd),
                   L"/c taskkill /f /im airmon.exe >nul 2>&1");
        cmd[ARRAYSIZE(cmd)-1] = 0;
        STARTUPINFOW si = { sizeof si };
        PROCESS_INFORMATION pi = {0};
        WCHAR full[MAX_PATH + 32];
        _snwprintf(full, ARRAYSIZE(full), L"%s", cmd);
        full[ARRAYSIZE(full)-1] = 0;
        if (CreateProcessW(NULL, full, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                           NULL, NULL, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 5000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }

    /* 2) 快捷方式 */
    if (shortcut_path(CSIDL_DESKTOPDIRECTORY, L"AirMon.lnk", lnk, MAX_PATH))
        DeleteFileW(lnk);

    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROGRAMS, NULL, 0, prog))) {
        WCHAR folder[MAX_PATH], f[MAX_PATH];
        join_path(folder, MAX_PATH, prog, APP_SHORT);
        join_path(f, MAX_PATH, folder, L"AirMon.lnk");
        DeleteFileW(f);
        join_path(f, MAX_PATH, folder, L"卸载 AirMon.lnk");
        DeleteFileW(f);
        RemoveDirectoryW(folder);
    }

    /* 3) 注册表 */
    reg_del_value(HKEY_CURRENT_USER, RUN_KEY, APP_SHORT);
    reg_del_tree(HKEY_CURRENT_USER, UNINST_KEY);

    /* 4) 文件。用户数据(airmon.db / airmon.ini / airmon.log)保留,
     *    免得"卸载顺手把历史数据删了" —— 那是用户几个月的记录。 */
    join_path(exe, MAX_PATH, dir, L"airmon.exe");
    join_path(html, MAX_PATH, dir, L"viewer.html");
    join_path(uninst, MAX_PATH, dir, UNINST_NAME);

    DeleteFileW(exe);
    DeleteFileW(html);

    /* 5) 卸载程序自己最后删(先把自己改名, 再让 cmd 删) */
    {
        WCHAR bat[MAX_PATH];
        WCHAR self[MAX_PATH];
        GetModuleFileNameW(NULL, self, MAX_PATH);
        GetTempPathW(MAX_PATH, bat);
        lstrcatW(bat, L"airmon_uninst.bat");

        HANDLE f = CreateFileW(bat, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, NULL);
        if (f != INVALID_HANDLE_VALUE) {
            /* 缓冲区要放得下两个 MAX_PATH 的路径(UTF-8 可能变长), 用 snprintf 防溢出 */
            char buf[4096];
            int n = _snprintf(buf, sizeof buf,
                "@echo off\r\n"
                "timeout /t 1 /nobreak >nul\r\n"
                "del /f /q \"%ls\"\r\n"
                "rmdir /q \"%ls\" 2>nul\r\n"
                "del /f /q \"%%~f0\"\r\n",
                self, dir);
            if (n > 0) {
                DWORD w = 0;
                WriteFile(f, buf, (DWORD)n, &w, NULL);
            }
            CloseHandle(f);

            STARTUPINFOW si = { sizeof si };
            PROCESS_INFORMATION pi = {0};
            WCHAR cmd[MAX_PATH * 2];
            _snwprintf(cmd, ARRAYSIZE(cmd), L"cmd.exe /c \"%s\"", bat);
            cmd[ARRAYSIZE(cmd)-1] = 0;
            if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                               NULL, NULL, &si, &pi)) {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }
        }
    }
}

/* ---------------- 界面 ---------------- */
static HWND mk(const WCHAR* cls, const WCHAR* text, DWORD style,
               int x, int y, int w, int h, int id)
{
    HWND c = CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | style,
                             x, y, w, h, g_hwnd, (HMENU)(INT_PTR)id,
                             GetModuleHandleW(NULL), NULL);
    if (c && g_font) SendMessageW(c, WM_SETFONT, (WPARAM)g_font, TRUE);
    return c;
}

static void browse(HWND hwnd)
{
    BROWSEINFOW bi = {0};
    WCHAR cur[MAX_PATH] = {0};
    WCHAR buf[MAX_PATH] = {0};
    LPITEMIDLIST pidl;
    int i;

    GetWindowTextW(g_path, cur, MAX_PATH);

    bi.hwndOwner = hwnd;
    bi.lpszTitle = L"选择 AirMon 的安装目录";
    bi.ulFlags  = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE | BIF_EDITBOX;
    pidl = SHBrowseForFolderW(&bi);
    if (!pidl) return;
    if (SHGetPathFromIDListW(pidl, buf)) {
        /* 如果用户选的是父目录, 自动补上 AirMon 子目录, 免得装散一地 */
        if (!wcsstr(buf, APP_SHORT)) {
            WCHAR tmp[MAX_PATH];
            join_path(tmp, MAX_PATH, buf, APP_SHORT);
            lstrcpynW(buf, tmp, MAX_PATH);
        }
        SetWindowTextW(g_path, buf);
    }
    CoTaskMemFree(pidl);
    (void)i;
}

static void on_install(HWND hwnd)
{
    WCHAR dir[MAX_PATH] = {0};
    GetWindowTextW(g_path, dir, MAX_PATH);
    if (!dir[0]) { set_status(L"请先选择安装目录"); return; }

    int autorun   = (SendMessageW(g_autorun, BM_GETCHECK, 0, 0) == BST_CHECKED);
    int desktop   = (SendMessageW(g_desktop, BM_GETCHECK, 0, 0) == BST_CHECKED);
    int startmenu = (SendMessageW(g_startmenu, BM_GETCHECK, 0, 0) == BST_CHECKED);
    int launch    = (SendMessageW(g_launch, BM_GETCHECK, 0, 0) == BST_CHECKED);

    EnableWindow(GetDlgItem(hwnd, ID_INSTALL), FALSE);
    EnableWindow(g_path, FALSE);
    EnableWindow(GetDlgItem(hwnd, ID_BROWSE), FALSE);
    g_busy = TRUE;

    if (do_install(dir, autorun, desktop, startmenu, launch)) {
        MessageBoxW(hwnd,
            L"安装完成。\n\n"
            L"· 桌面上有 AirMon 快捷方式\n"
            L"· 右键托盘图标可「连接设备」「发送对时」「打开数据网页」\n"
            L"· 数据网页地址: http://127.0.0.1:8787/\n\n"
            L"卸载: 设置 → 应用 → AirMon, 或安装目录里的 uninstall.exe\n"
            L"(卸载不会删除 airmon.db, 历史数据会保留)",
            L"AirMon", MB_ICONINFORMATION);
        DestroyWindow(hwnd);
        return;
    }

    EnableWindow(GetDlgItem(hwnd, ID_INSTALL), TRUE);
    EnableWindow(g_path, TRUE);
    EnableWindow(GetDlgItem(hwnd, ID_BROWSE), TRUE);
    g_busy = FALSE;
}

static LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE:
        g_hwnd = hwnd;
        {
            NONCLIENTMETRICSW ncm = { sizeof ncm };
            if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof ncm, &ncm, 0))
                g_font = CreateFontIndirectW(&ncm.lfMessageFont);
        }

        mk(L"STATIC", L"安装 AirMon 空气质量监测", 0, 20, 18, 460, 24, 0);
        mk(L"STATIC", L"选择安装位置：", 0, 20, 56, 200, 18, 0);

        g_path = mk(L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL, 20, 78, 380, 24, ID_PATH);
        mk(L"BUTTON", L"浏览…", BS_PUSHBUTTON, 410, 78, 70, 24, ID_BROWSE);

        g_autorun   = mk(L"BUTTON", L"开机自动启动", BS_AUTOCHECKBOX, 20, 118, 200, 20, ID_AUTORUN);
        g_desktop   = mk(L"BUTTON", L"创建桌面快捷方式", BS_AUTOCHECKBOX, 20, 142, 200, 20, ID_DESKTOP);
        g_startmenu = mk(L"BUTTON", L"创建开始菜单快捷方式", BS_AUTOCHECKBOX, 20, 166, 240, 20, ID_STARTMENU);
        g_launch    = mk(L"BUTTON", L"安装完成后立即启动", BS_AUTOCHECKBOX, 20, 190, 240, 20, ID_LAUNCH);

        g_status = mk(L"STATIC", L"准备就绪", SS_LEFT, 20, 224, 460, 40, ID_STATUS);

        mk(L"BUTTON", L"安装", BS_DEFPUSHBUTTON, 320, 272, 76, 28, ID_INSTALL);
        mk(L"BUTTON", L"取消", BS_PUSHBUTTON, 404, 272, 76, 28, ID_CANCEL);

        SendMessageW(g_autorun, BM_SETCHECK, BST_CHECKED, 0);
        SendMessageW(g_desktop, BM_SETCHECK, BST_CHECKED, 0);
        SendMessageW(g_startmenu, BM_SETCHECK, BST_CHECKED, 0);
        SendMessageW(g_launch, BM_SETCHECK, BST_CHECKED, 0);

        {
            WCHAR def[MAX_PATH];
            default_dir(def, MAX_PATH);
            SetWindowTextW(g_path, def);
        }
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case ID_BROWSE:  browse(hwnd); break;
        case ID_INSTALL: if (!g_busy) on_install(hwnd); break;
        case ID_CANCEL:  DestroyWindow(hwnd); break;
        }
        return 0;

    case WM_CLOSE:
        if (g_busy) return 0;      /* 安装过程中不许关 */
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        if (g_font) DeleteObject(g_font);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

/* 入口用标准 WinMain(而不是 wWinMain):
 * 这台机器上 -municode 在链接期没生效, CRT 仍走 WinMainCRTStartup -> WinMain,
 * 只提供 wWinMain 会导致程序静默不执行。宽字符命令行自己用 GetCommandLineW 取,
 * 反正后面全是 W 版本 API, 不受影响。 */
int WINAPI WinMain(HINSTANCE inst, HINSTANCE prev, LPSTR cmdlineA, int show)
{
    (void)prev; (void)show; (void)cmdlineA;

    LPWSTR cmdline = GetCommandLineW();

    /* 命令行: /uninstall */
    if (cmdline && wcsstr(cmdline, L"/uninstall")) {
        WCHAR dir[MAX_PATH] = {0};
        GetModuleFileNameW(NULL, dir, MAX_PATH);
        WCHAR* s = wcsrchr(dir, L'\\');
        if (s) *s = 0;
        do_uninstall(dir);
        return 0;
    }

    /* 静默安装: /S [/D=目录]  —— /D 便于脚本/自动化指定目录 */
    if (cmdline && wcsstr(cmdline, L"/S")) {
        WCHAR dir[MAX_PATH];
        default_dir(dir, MAX_PATH);

        {
            WCHAR* d = wcsstr(cmdline, L"/D=");
            if (d) {
                d += 3;
                WCHAR val[MAX_PATH] = {0};
                int i = 0;
                /* 到下一个 / 参数或结尾为止; 允许带引号 */
                if (*d == L'"') {
                    d++;
                    while (*d && *d != L'"' && i < MAX_PATH - 1) val[i++] = *d++;
                } else {
                    while (*d && *d != L' ' && *d != L'/' && i < MAX_PATH - 1) val[i++] = *d++;
                }
                val[i] = 0;
                if (val[0]) lstrcpynW(dir, val, MAX_PATH);
            }
        }

        return do_install(dir, 1, 1, 1, 0) ? 0 : 1;
    }

    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    InitCommonControls();

    WNDCLASSEXW wc = { sizeof wc };
    wc.lpfnWndProc   = wnd_proc;
    wc.hInstance     = inst;
    wc.hCursor       = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"AirMonSetup";
    wc.hIcon         = LoadIconW(NULL, IDI_APPLICATION);
    RegisterClassExW(&wc);

    HWND h = CreateWindowExW(0, L"AirMonSetup", L"AirMon 安装程序",
                             WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                             CW_USEDEFAULT, CW_USEDEFAULT, 510, 350,
                             NULL, NULL, inst, NULL);
    if (!h) return 1;

    /* 居中 */
    {
        RECT r, w;
        GetWindowRect(h, &r);
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &w, 0);
        SetWindowPos(h, NULL,
                     (w.right - w.left - (r.right - r.left)) / 2 + w.left,
                     (w.bottom - w.top - (r.bottom - r.top)) / 2 + w.top,
                     0, 0, SWP_NOSIZE | SWP_NOZORDER);
    }

    ShowWindow(h, SW_SHOW);
    UpdateWindow(h);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        if (!IsDialogMessageW(h, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    CoUninitialize();
    return 0;
}
