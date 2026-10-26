/*
 * airmon.c - PB03F-AIR 空气质量监测托盘上位机
 *
 * 半透明黑色悬浮窗, 可拖动; 被动监听 BLE 广播 + 可主动连接设备
 * (GATT 订阅传感通知), SQLite 存储与历史曲线。
 * Windows 10 1809+ (蓝牙 LE WinRT API)。
 *
 * 托盘图标不是"加了就一定有":
 *   - 以管理员身份运行(或低完整性进程)时 Shell_NotifyIcon 会失败(错误 5)
 *   - 资源管理器重启后图标会丢
 * 所以这里做了三件事: 校验添加结果、监听 TaskbarCreated 重加、
 * 再挂一个全局热键兜底 —— 保证窗口藏起来后一定能找回来。
 *
 * 托盘图标上直接显示 AQI 数字, 数字按等级绿/黄/红, 背景透明。
 */
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <winsvc.h>
#include <stdio.h>
#include "airmon.h"

#define WM_TRAYICON (WM_USER + 1)
#define WM_APP_NOTIFY (WM_APP + 5)   /* 任意线程 -> UI: 发系统通知, wParam=air_notify_kind_t */
#define HOTKEY_TOGGLE 1
#define HOTKEY_QUIT   2   /* 兜底退出: 托盘菜单万一失效, 也能把程序关掉 */

/* 兜底热键按顺序试, 第一个注册成功的就用它 —— Ctrl+Alt+A 常被别的程序占用 */
typedef struct { UINT mods; UINT vk; const WCHAR* name; } hk_cand_t;
static const hk_cand_t HK_CANDS[] = {
    { MOD_CONTROL | MOD_ALT,   'A',    L"Ctrl+Alt+A" },
    { MOD_CONTROL | MOD_ALT,   'M',    L"Ctrl+Alt+M" },
    { MOD_CONTROL | MOD_SHIFT, 'A',    L"Ctrl+Shift+A" },
    { MOD_CONTROL | MOD_ALT,   VK_F9,  L"Ctrl+Alt+F9" },
};
static WCHAR g_hotkey_name[32] = L"";

/* 兜底退出键。托盘菜单依赖前台窗口/提权状态, 有可能失效(菜单闪一下就没了),
 * 那时用户就"关都关不了"。这里给一个不依赖 UI 的退出通道。 */
static BOOL g_hotkey_quit_ok = FALSE;
static const hk_cand_t HK_QUIT_CANDS[] = {
    { MOD_CONTROL | MOD_ALT,   'Q', L"Ctrl+Alt+Q" },
    { MOD_CONTROL | MOD_SHIFT, 'Q', L"Ctrl+Shift+Q" },
};

static const WCHAR CLS_NAME[] = L"AIRMON_MAIN";
static const WCHAR TITLE[]    = L"AirMon 空气质量监测";

static HWND   g_hwnd;
static HICON  g_hicon;
static NOTIFYICONDATAW g_nid;
static BOOL   g_tray_shown = FALSE;
static BOOL   g_tray_ok    = FALSE;   /* 图标是否真的加成功了 */
static BOOL   g_hotkey_ok  = FALSE;
static BOOL   g_ballooned  = FALSE;
static UINT   g_wm_taskbar_created = 0;

/* -------- UI 状态: 最新一帧数据, 由 BLE/GATT 线程通过 WM_APP_DATA 更新 -------- */
air_data_t g_last = {0};

/* ---------------- 崩溃自诊断 ----------------
 * 崩溃时把异常码、出错地址、所属模块写进 airmon.log,
 * 这样即使我看不到现场, 也能知道崩在哪个模块。 */
static void crash_write(const WCHAR* text)
{
    WCHAR path[MAX_PATH];
    HANDLE f;
    DWORD wr;

    lstrcpynW(path, air_cfg_path(), MAX_PATH);
    {
        WCHAR* slash = wcsrchr(path, L'\\');
        if (slash) lstrcpynW(slash + 1, L"airmon.log", MAX_PATH - (int)(slash + 1 - path));
    }
    f = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                    OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return;
    SetFilePointer(f, 0, NULL, FILE_END);
    WriteFile(f, text, (DWORD)(lstrlenW(text) * sizeof(WCHAR)), &wr, NULL);
    CloseHandle(f);
}

static LONG WINAPI crash_filter(EXCEPTION_POINTERS* ep)
{
    WCHAR buf[512];
    WCHAR mod[MAX_PATH];
    PEXCEPTION_RECORD er = ep ? ep->ExceptionRecord : NULL;

    lstrcpynW(mod, L"?", ARRAYSIZE(mod));
    if (er) {
        HMODULE h = NULL;
        if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               (LPCWSTR)(void*)er->ExceptionAddress, &h) && h) {
            GetModuleFileNameW(h, mod, ARRAYSIZE(mod));
        }
        /* wsprintfW 不走 CRT, 崩溃现场更安全 */
        wsprintfW(buf, L"\r\n!!! 崩溃 code=0x%08lX addr=%p\r\n    模块: %s\r\n",
                  (unsigned long)er->ExceptionCode, er->ExceptionAddress, mod);
    } else {
        lstrcpynW(buf, L"\r\n!!! 崩溃 (无异常记录)\r\n", ARRAYSIZE(buf));
    }
    crash_write(buf);
    return EXCEPTION_EXECUTE_HANDLER;
}

/* 配置/状态文件(exe 同目录): 窗口位置 + 置顶 + 上次设备地址 */
const WCHAR* air_cfg_path(void)
{
    static WCHAR path[MAX_PATH] = {0};
    if (!path[0]) {
        WCHAR* slash;
        GetModuleFileNameW(NULL, path, MAX_PATH);
        slash = wcsrchr(path, L'\\');
        if (slash) *(slash + 1) = 0;
        lstrcpynW(path + lstrlenW(path), L"airmon.ini",
                  MAX_PATH - lstrlenW(path));
    }
    return path;
}

/* ---------------- 托盘图标: AQI 数字, 绿/黄/红字, 背景透明 ---------------- */
static int  g_icon_aqi  = -2;    /* 当前图标上的 AQI, -2=还没画过 */
static BOOL g_icon_have = FALSE;
/* 系统对托盘图标的引用是异步的: NIM_MODIFY 返回不代表旧图标已经没人用了。
 * 所以旧图标延后一代再销毁, 否则可能在启动/刷新时崩溃。 */
static HICON g_icon_retired = NULL;

/* 注意: 以前这里有个 ICON_STALE_MS(12 秒没新数据就当"无数据"), 已经去掉 ——
 * 断开连接时托盘会变回"--", 用户不想要这个。现在收到过就一直显示最后一次的值。 */

static void build_tip(WCHAR* buf, int cap, int aqi, BOOL have)
{
    const WCHAR* st;
    if (!have)           st = L"无数据";
    else if (aqi <= 50)  st = L"优";
    else if (aqi <= 100) st = L"良";
    else if (aqi <= 150) st = L"轻度污染";
    else if (aqi <= 200) st = L"中度污染";
    else if (aqi <= 300) st = L"重度污染";
    else                 st = L"严重污染";

    if (have) {
        if (g_hotkey_ok)
            swprintf(buf, cap, L"AirMon 空气质量监测\nAQI %d %s\n双击图标或按 %s 显示/隐藏",
                     aqi, st, g_hotkey_name);
        else
            swprintf(buf, cap, L"AirMon 空气质量监测\nAQI %d %s\n双击图标显示/隐藏", aqi, st);
    } else {
        if (g_hotkey_ok)
            swprintf(buf, cap, L"AirMon 空气质量监测\n%s\n双击图标或按 %s 显示/隐藏",
                     st, g_hotkey_name);
        else
            swprintf(buf, cap, L"AirMon 空气质量监测\n%s\n双击图标显示/隐藏", st);
    }
}

/* 按最新数据刷新托盘图标; 只有 AQI/有无数据变了才重画 */
static void update_tray_icon(BOOL force)
{
    air_data_t d;
    BOOL have = FALSE;
    int  aqi  = 0;

    store_get_last(&d);
    /* 只要收到过数据, 托盘就一直显示最后那一帧的值 —— 断开连接后不再
     * 变回"--"。用户明确要这个行为: 断开时显示上次的数据, 比两条杠有用。
     * 只有从启动到现在一次都没收到过数据, 才显示"--"。 */
    if (d.ft.dwLowDateTime || d.ft.dwHighDateTime) {
        have = TRUE;
        aqi  = (int)d.aqi;
    }

    if (!force && have == g_icon_have && aqi == g_icon_aqi) return;
    g_icon_have = have;
    g_icon_aqi  = aqi;

    {
        HICON ni = trayicon_make(aqi, have);
        HICON old;
        WCHAR tip[192];

        if (!ni) return;
        old = g_hicon;
        g_hicon = ni;

        if (g_tray_ok) {
            build_tip(tip, ARRAYSIZE(tip), aqi, have);
            lstrcpynW(g_nid.szTip, tip, ARRAYSIZE(g_nid.szTip));
            g_nid.hIcon  = ni;
            g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
            Shell_NotifyIconW(NIM_MODIFY, &g_nid);

            /* 旧图标延后一代销毁: 托盘可能还没放手 */
            if (old) {
                if (g_icon_retired) DestroyIcon(g_icon_retired);
                g_icon_retired = old;
            }
        } else if (old) {
            /* 还没挂到托盘, 系统没引用, 可以直接销毁 */
            DestroyIcon(old);
        }
    }
}

static void tray_remove(void)
{
    if (g_tray_shown) {
        Shell_NotifyIconW(NIM_DELETE, &g_nid);
        g_tray_shown = FALSE;
        g_tray_ok    = FALSE;
    }
}

/* 返回图标是否真的加上了 */
static BOOL tray_add(void)
{
    WCHAR tip[192];

    build_tip(tip, ARRAYSIZE(tip), g_icon_have ? g_icon_aqi : 0, g_icon_have);

    ZeroMemory(&g_nid, sizeof g_nid);
    g_nid.cbSize           = sizeof g_nid;
    g_nid.hWnd             = g_hwnd;
    g_nid.uID              = 1;
    g_nid.uFlags           = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;
    g_nid.hIcon            = g_hicon ? g_hicon : LoadIconW(NULL, (LPCWSTR)IDI_APPLICATION);
    lstrcpynW(g_nid.szTip, tip, ARRAYSIZE(g_nid.szTip));

    g_tray_shown = Shell_NotifyIconW(NIM_ADD, &g_nid) ? TRUE : FALSE;
    g_tray_ok    = g_tray_shown;
    return g_tray_ok;
}

/* 藏起来时弹个气泡告诉用户去哪了(只弹一次) */
static void tray_balloon_once(const WCHAR* info)
{
    if (!g_tray_ok || g_ballooned) return;
    g_ballooned = TRUE;

    g_nid.uFlags = NIF_INFO;
    g_nid.dwInfoFlags = NIIF_INFO;
    lstrcpynW(g_nid.szInfoTitle, L"AirMon", ARRAYSIZE(g_nid.szInfoTitle));
    lstrcpynW(g_nid.szInfo, info, ARRAYSIZE(g_nid.szInfo));
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
}

/* 托盘图标和热键都不可用时, 藏起来就找不回来了 */
static BOOL can_hide(void)
{
    return (g_tray_ok || g_hotkey_ok) ? TRUE : FALSE;
}

/* 每次都要弹的那种气泡(用于断开提示) */
static void tray_balloon_now(const WCHAR* title, const WCHAR* body)
{
    if (!g_tray_ok) return;
    g_nid.uFlags = NIF_INFO;
    g_nid.dwInfoFlags = NIIF_INFO;
    lstrcpynW(g_nid.szInfoTitle, title, ARRAYSIZE(g_nid.szInfoTitle));
    lstrcpynW(g_nid.szInfo, body, ARRAYSIZE(g_nid.szInfo));
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
}

/* 发系统通知: 先试 WinRT Toast(不依赖托盘), 失败再用托盘气泡兜底。
 *
 * 这个程序是常驻监视用的, 断线重连可能一天发生几十次。每次都弹 Windows 通知
 * 会很烦, 所以只在前几次弹, 之后静默(日志里仍然有记录)。
 * 重连成功也只在前面几次提示一下。 */
#define NOTIFY_MAX_POPUPS 3
static void do_notify(int kind)
{
    const WCHAR* title = L"AirMon 空气质量监测";
    const WCHAR* body;
    static int shown = 0;

    switch (kind) {
    case AIR_NOTIFY_LOST:        body = L"与 PB03F-AIR 的连接已断开";            break;
    case AIR_NOTIFY_RECONNECTED: body = L"已重新连接 PB03F-AIR，继续接收数据";   break;
    default:                     body = L"重连已停止，请检查设备是否上电、在范围内"; break;
    }

    if (shown >= NOTIFY_MAX_POPUPS) {
        air_log("通知: 已达弹窗上限(%d 次), 本条静默: %ls", NOTIFY_MAX_POPUPS, body);
        return;
    }
    shown++;

    if (!notify_toast(title, body))
        tray_balloon_now(title, body);
}

/* 任意线程可调: 转投到 UI 线程再发, 避免跨线程碰托盘状态 */
void air_notify(int kind)
{
    if (g_hwnd) PostMessageW(g_hwnd, WM_APP_NOTIFY, (WPARAM)kind, 0);
}

void air_toggle_visible(void)
{
    if (IsWindowVisible(g_hwnd)) {
        if (!can_hide()) {
            MessageBoxW(NULL,
                L"无法隐藏窗口：托盘图标没能创建（常见原因：程序以管理员身份运行，"
                L"而资源管理器不是），备用快捷键也都被占用了。\n\n"
                L"窗口先保持显示。",
                TITLE, MB_ICONWARNING);
            return;
        }
        ShowWindow(g_hwnd, SW_HIDE);
        {
            WCHAR info[192];
            if (g_tray_ok && g_hotkey_ok)
                swprintf(info, ARRAYSIZE(info),
                         L"已隐藏到托盘。\n双击托盘图标或按 %s 可以再叫出来。", g_hotkey_name);
            else if (g_tray_ok)
                lstrcpynW(info, L"已隐藏到托盘。\n双击托盘图标可以再叫出来。", ARRAYSIZE(info));
            else
                swprintf(info, ARRAYSIZE(info),
                         L"已隐藏。\n按 %s 可以再叫出来。", g_hotkey_name);
            tray_balloon_once(info);
        }
    } else {
        ShowWindow(g_hwnd, SW_SHOWNOACTIVATE);
        ui_render(g_hwnd);
    }
}

const WCHAR* air_hotkey_name(void)
{
    return g_hotkey_name;
}

static void show_main(void)
{
    ShowWindow(g_hwnd, SW_SHOWNOACTIVATE);
    ui_render(g_hwnd);      /* 分层窗口必须主动推一次内容 */
}

/* 重启 Windows 蓝牙服务(bthserv)。
 *
 * 为什么需要它: 当设备被系统蓝牙栈"粘住"(旧版本残留、或某个进程崩溃时
 * 没放开 GATT 会话), 设备会停止广播, 手机和本机都搜不到。用户只能
 * 关一次蓝牙再打开、甚至重启电脑才能恢复。
 * 重启 bthserv 等价于"关一次蓝牙再打开", 但不用动硬件开关, 也不需要重启。
 *
 * 需要管理员权限; 没有权限时返回 FALSE, 由调用方提示用户手动操作。 */
BOOL air_restart_bt_service(void)
{
    SC_HANDLE scm, svc;
    SERVICE_STATUS st;
    BOOL ok = FALSE;

    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) {
        air_log("重启蓝牙服务: OpenSCManager 失败 err=%lu", GetLastError());
        return FALSE;
    }
    svc = OpenServiceW(scm, L"bthserv", SERVICE_STOP | SERVICE_START | SERVICE_QUERY_STATUS);
    if (!svc) {
        air_log("重启蓝牙服务: OpenService 失败 err=%lu (多半是没有管理员权限)", GetLastError());
        CloseServiceHandle(scm);
        return FALSE;
    }

    air_log("重启蓝牙服务: 正在停止 bthserv");
    if (ControlService(svc, SERVICE_CONTROL_STOP, &st)) {
        /* 等它真的停下(最多 10 秒) */
        for (int i = 0; i < 50; i++) {
            SERVICE_STATUS cur;
            if (!QueryServiceStatus(svc, &cur)) break;
            if (cur.dwCurrentState == SERVICE_STOPPED) break;
            Sleep(200);
        }
    }
    air_log("重启蓝牙服务: 正在启动 bthserv");
    if (StartServiceW(svc, 0, NULL) ||
        GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) {
        ok = TRUE;
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    air_log("重启蓝牙服务: %s", ok ? "完成" : "失败");
    return ok;
}

static LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    /* 资源管理器重启后托盘会被清空, 必须重新添加 */
    if (g_wm_taskbar_created && msg == g_wm_taskbar_created) {
        tray_remove();
        tray_add();
        return 0;
    }

    switch (msg) {
    case WM_CREATE:
        SetTimer(hwnd, 1, 1000, NULL);   /* 1s 入库节拍 */
        for (int i = 0; i < (int)ARRAYSIZE(HK_CANDS); i++) {
            if (RegisterHotKey(hwnd, HOTKEY_TOGGLE, HK_CANDS[i].mods, HK_CANDS[i].vk)) {
                g_hotkey_ok = TRUE;
                lstrcpynW(g_hotkey_name, HK_CANDS[i].name, ARRAYSIZE(g_hotkey_name));
                break;
            }
        }
        for (int i = 0; i < (int)ARRAYSIZE(HK_QUIT_CANDS); i++) {
            if (RegisterHotKey(hwnd, HOTKEY_QUIT, HK_QUIT_CANDS[i].mods, HK_QUIT_CANDS[i].vk)) {
                g_hotkey_quit_ok = TRUE;
                air_log("main: 退出快捷键 %ls", HK_QUIT_CANDS[i].name);
                break;
            }
        }
        if (!g_hotkey_quit_ok) air_log("main: 退出快捷键注册失败(被占用)");
        return 0;

    case WM_TIMER:
        if (wp == 1) {
            store_tick();
            ui_refresh_series();         /* 曲线也跟着时间窗往前滑 */
            update_tray_icon(FALSE);     /* 数据断了图标要变 "--" */
            InvalidateRect(hwnd, NULL, FALSE);
        }
        return 0;

    case WM_HOTKEY:
        if (wp == HOTKEY_TOGGLE) air_toggle_visible();
        else if (wp == HOTKEY_QUIT) {
            air_log("main: 退出快捷键按下, 关闭程序");
            DestroyWindow(hwnd);
        }
        return 0;

    case WM_APP_DATA:
        ui_refresh_series();         /* 每来一帧就重查, 曲线立刻往前走 */
        update_tray_icon(FALSE);
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;

    case WM_APP_GATT:
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;

    case WM_APP_BLE:
        ui_note_ble((int)wp);            /* 1=started 2=failed 3=对时成功 */
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;

    case WM_APP_NOTIFY:
        do_notify((int)wp);
        return 0;

    case WM_PAINT:
        ui_render(hwnd);
        ValidateRect(hwnd, NULL);
        return 0;

    case WM_LBUTTONDOWN:
    case WM_LBUTTONUP:
    case WM_MOUSEMOVE:
    case WM_RBUTTONUP:
    case WM_CAPTURECHANGED:
        if (ui_mouse(hwnd, msg, wp, lp)) return 0;
        return 0;

    case WM_TRAYICON:
        if (LOWORD(lp) == WM_LBUTTONUP || LOWORD(lp) == WM_LBUTTONDBLCLK ||
            LOWORD(lp) == NIN_SELECT) {
            air_toggle_visible();
        } else if (LOWORD(lp) == WM_RBUTTONUP || LOWORD(lp) == WM_CONTEXTMENU) {
            ui_tray_menu(hwnd);
        }
        return 0;

    case WM_ERASEBKGND:
        return 1;

    case WM_DESTROY:
        KillTimer(hwnd, 1);
        if (g_hotkey_ok) { UnregisterHotKey(hwnd, HOTKEY_TOGGLE); g_hotkey_ok = FALSE; }
        if (g_hotkey_quit_ok) { UnregisterHotKey(hwnd, HOTKEY_QUIT); g_hotkey_quit_ok = FALSE; }
        tray_remove();
        gatt_stop();
        ble_stop();
        store_close();
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

/* 初始位置: 上次退出时的位置; 没有就贴工作区右侧 */
static void place_window(int* x, int* y)
{
    int px = GetPrivateProfileIntW(L"win", L"x", -1, air_cfg_path());
    int py = GetPrivateProfileIntW(L"win", L"y", -1, air_cfg_path());
    if (px >= 0 && py >= 0) { *x = px; *y = py; return; }

    {
        RECT wa;
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0);
        *x = wa.right - AIRMON_W - 24;
        *y = wa.top + 80;
    }
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, PWSTR cmd, int show)
{
    WNDCLASSW wc = {0};
    int x, y;

    (void)hPrev; (void)cmd; (void)show;

    /* ---- 主动申请管理员权限 ----
     * 为什么要管理员: 设备被系统蓝牙栈粘住时, 唯一有效的释放手段是重启
     * bthserv 服务; 那需要管理员权限。所以启动时如果没有权限就自我提权一次
     * (会弹 UAC 让你点同意), 提到权限后再继续。
     * 用 "--elevated" 参数标记已经提过权, 避免无限递归。 */
    if (!wcsstr(GetCommandLineW(), L"--elevated")) {
        BOOL is_admin = FALSE;
        {
            PSID sid = NULL;
            SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
            if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                         DOMAIN_ALIAS_RID_ADMINS, 0,0,0,0,0,0, &sid)) {
                CheckTokenMembership(NULL, sid, &is_admin);
                FreeSid(sid);
            }
        }
        if (!is_admin) {
            WCHAR exe[MAX_PATH];
            HINSTANCE hi;
            GetModuleFileNameW(NULL, exe, MAX_PATH);
            hi = ShellExecuteW(NULL, L"runas", exe, L"--elevated",
                               NULL, SW_SHOWNORMAL);
            if ((INT_PTR)hi > 32) {
                /* 提权实例已启动, 当前这个直接退出 */
                return 0;
            }
            /* 用户点了"否": 继续以普通权限运行, 只是没法重启蓝牙服务 */
        }
    }

    wc.lpfnWndProc   = wnd_proc;
    wc.hInstance     = hInst;
    wc.lpszClassName = CLS_NAME;
    wc.hCursor       = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = NULL;            /* 分层窗口自己画, 不用背景刷 */
    RegisterClassW(&wc);

    SetUnhandledExceptionFilter(crash_filter);   /* 崩溃时留证据 */

    g_wm_taskbar_created = RegisterWindowMessageW(L"TaskbarCreated");

    place_window(&x, &y);

    g_hwnd = CreateWindowExW(WS_EX_LAYERED | WS_EX_TOOLWINDOW |
                             WS_EX_TOPMOST | WS_EX_NOACTIVATE,
                             CLS_NAME, TITLE, WS_POPUP,
                             x, y, AIRMON_W, AIRMON_H,
                             NULL, NULL, hInst, NULL);
    if (!g_hwnd) return 1;

    g_hicon = trayicon_make(0, FALSE);       /* 初始: 无数据, 显示 "--" */
    if (!g_hicon) g_hicon = LoadIconW(NULL, (LPCWSTR)IDI_APPLICATION);
    g_icon_have = FALSE;                     /* 与 g_hicon 内容一致, 避免重复造图标 */
    g_icon_aqi  = 0;
    ui_init(g_hwnd);                /* 应用上次记住的"窗口置顶"设置 */

    if (store_open() != 0) {
        MessageBoxW(NULL, L"数据库初始化失败", TITLE, MB_ICONERROR);
        return 1;
    }
    ui_restore_view();              /* 按上次保存的范围/指标查一次, 曲线区立刻有内容 */
    air_log("=== AirMon 启动 ===");
    {
        /* 诊断用: airmon.exe --no-ble 可跳过蓝牙, 用来判断崩溃是否与蓝牙有关 */
        BOOL no_ble = (wcsstr(GetCommandLineW(), L"--no-ble") != NULL);
        if (no_ble) {
            air_log("main: --no-ble, 跳过蓝牙监听");
        } else if (ble_start(g_hwnd) != 0) {
            air_log("main: ble_start 返回失败(线程没起来)");
            MessageBoxW(NULL, L"BLE 监听启动失败 (需要 Win10 1809+, 蓝牙已开启)", TITLE, MB_ICONWARNING);
        }
    }
    air_log("main: gatt_start");
    gatt_start(g_hwnd);
    air_log("main: timesync_start");
    /* 独立对时线程已停用。
     * 它会自己 FromBluetoothAddressAsync 再连一次设备, 于是同一台设备上
     * 有两条 GATT 客户端 —— 对时那条结束时把共享链路 Close 掉, 主连接就断了。
     * 现在对时由 gatt.c 在已建立的连接上顺手写一次(timesync_write_on_service)。 */
    /* timesync_start(g_hwnd); */

    /* 启动时绝不做任何"清理设备占用"的动作。
     *
     * 之前这里起了个线程调 gatt_release_device(), 而那个函数内部用的是
     * BluetoothLEDevice.FromBluetoothAddressAsync —— 这个 API 一调用就会
     * 主动去连设备! 所以"清理"变成了"开机自动连一次", 而且它 Close 的只是
     * 自己新开的会话, 之前残留的那个反而更稳了。
     * 现在直接去掉: 程序启动只做被动广播监听, 不碰设备。 */

    air_log("main: tray_add");
    tray_add();                  /* 用当前 g_hicon 挂到托盘 */
    air_log("main: update_tray_icon");
    update_tray_icon(FALSE);     /* 数据若已到, 刷新成真实 AQI(此时才 NIM_MODIFY) */
    air_log("main: show_main");
    show_main();
    air_log("main: 启动完成");

    {
        MSG msg;
        while (GetMessageW(&msg, NULL, 0, 0) > 0) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    if (g_hicon) DestroyIcon(g_hicon);
    return 0;
}
