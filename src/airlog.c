/*
 * airlog.c - 极简日志, 写到 exe 同目录的 airmon.log
 *
 * 蓝牙出问题时光看界面判断不了是"监听器没启动"还是"启动了但没广播",
 * 所以把关键 HRESULT 和状态都落到文件里, 方便排查。
 * 单文件超过 256KB 时自动清空重来, 不会无限增长。
 */
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include "airmon.h"

static CRITICAL_SECTION g_log_cs;
static BOOL g_log_init = FALSE;

static void log_path(WCHAR* out, int cap)
{
    WCHAR* slash;
    lstrcpynW(out, air_cfg_path(), cap);          /* ...\airmon.ini */
    slash = wcsrchr(out, L'\\');
    if (slash) lstrcpynW(slash + 1, L"airmon.log", cap - (int)(slash + 1 - out));
}

void air_log(const char* fmt, ...)
{
    WCHAR path[MAX_PATH];
    WCHAR line[512];
    char  utf8[512];
    va_list ap;
    HANDLE f;
    DWORD wr;
    LARGE_INTEGER sz;

    if (!g_log_init) {
        InitializeCriticalSection(&g_log_cs);
        g_log_init = TRUE;
    }

    va_start(ap, fmt);
    _vsnprintf(utf8, sizeof utf8 - 1, fmt, ap);
    va_end(ap);
    utf8[sizeof utf8 - 1] = 0;

    /* 转成 UTF-16, 便于记事本直接看中文 */
    MultiByteToWideChar(CP_UTF8, 0, utf8, -1, line, ARRAYSIZE(line) - 1);
    line[ARRAYSIZE(line) - 1] = 0;

    EnterCriticalSection(&g_log_cs);
    log_path(path, MAX_PATH);

    f = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                    OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        /* 太大就清空 */
        sz.LowPart = GetFileSize(f, (DWORD*)&sz.HighPart);
        if (sz.QuadPart > 256 * 1024) {
            CloseHandle(f);
            f = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (f == INVALID_HANDLE_VALUE) goto out;
        }
        SetFilePointer(f, 0, NULL, FILE_END);
        /* 加时间戳 */
        {
            SYSTEMTIME st;
            WCHAR ts[64];
            GetLocalTime(&st);
            swprintf(ts, ARRAYSIZE(ts), L"[%02d:%02d:%02d.%03d] ",
                     st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
            WriteFile(f, ts, (DWORD)(lstrlenW(ts) * sizeof(WCHAR)), &wr, NULL);
        }
        WriteFile(f, line, (DWORD)(lstrlenW(line) * sizeof(WCHAR)), &wr, NULL);
        {
            static const WCHAR nl[] = L"\r\n";
            WriteFile(f, nl, 2 * sizeof(WCHAR), &wr, NULL);
        }
        CloseHandle(f);
    }
out:
    LeaveCriticalSection(&g_log_cs);
}
