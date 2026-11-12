/*
 * httpd.c - 极简 HTTP 服务, 让 viewer.html 能"动态"看数据
 *
 * 解决的问题:
 *   以前看数据必须点「查看数据.bat」→ dbjson.exe 导出静态 airmon.json
 *   → 手动拖进 viewer.html。数据是快照, 想看新的就得再来一遍。
 *   想直接让页面 fetch 本地 json 是不行的: 浏览器用 file:// 打开页面时
 *   禁止读本地文件(fetch/XHR 都会被 CORS 挡掉)。
 *
 * 所以把服务做进 airmon.exe 自己(它本来就常驻在跑), 只监听 127.0.0.1:
 *   GET /                  -> 返回 viewer.html
 *   GET /api/data?from=&to= -> 返回 JSON, 格式与 tools/dbjson.c 完全一致
 *
 * 页面用 http 打开时自动轮询 /api/data, 数据就是活的。
 * 用 file:// 打开时仍然保留原来的拖拽方式, 两条路都通。
 *
 * 安全: 只绑 127.0.0.1, 不对外网/局域网开放; 只处理 GET; 不做目录遍历,
 *       静态文件只认 viewer.html 这一个名字。
 */
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include "airmon.h"
#include "../third_party/sqlite3.h"

#define HTTPD_PORT_DEFAULT 8787
#define HTTPD_MAX_REQ      8192

static volatile LONG g_httpd_run = 0;
static int           g_httpd_port = HTTPD_PORT_DEFAULT;

/* ---------------- 动态缓冲 ---------------- */
typedef struct {
    char*  p;
    size_t len;
    size_t cap;
} buf_t;

static void buf_init(buf_t* b) { b->p = NULL; b->len = 0; b->cap = 0; }

static int buf_need(buf_t* b, size_t extra)
{
    if (b->len + extra + 1 <= b->cap) return 0;
    size_t nc = b->cap ? b->cap : 65536;
    while (nc < b->len + extra + 1) nc *= 2;
    char* np = (char*)realloc(b->p, nc);
    if (!np) return -1;
    b->p = np;
    b->cap = nc;
    return 0;
}

static void buf_addf(buf_t* b, const char* fmt, ...)
{
    if (buf_need(b, 256) != 0) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(b->p + b->len, b->cap - b->len, fmt, ap);
    va_end(ap);
    if (n > 0) {
        if ((size_t)n >= b->cap - b->len) {
            /* 不够就扩到刚好, 再写一次 */
            if (buf_need(b, (size_t)n) != 0) return;
            va_start(ap, fmt);
            n = vsnprintf(b->p + b->len, b->cap - b->len, fmt, ap);
            va_end(ap);
        }
        if (n > 0) b->len += (size_t)n;
    }
}

static void buf_free(buf_t* b) { free(b->p); b->p = NULL; b->len = b->cap = 0; }

/* ---------------- 数据库路径(与 store.c 一致: exe 同目录) ---------------- */
static void db_path_a(char* out, size_t cap)
{
    GetModuleFileNameA(NULL, out, (DWORD)cap);
    char* slash = strrchr(out, '\\');
    if (slash) *(slash + 1) = 0;
    strncat(out, "airmon.db", cap - strlen(out) - 1);
}

/* viewer.html 在 exe 的上一级(airmon\viewer.html, exe 在 airmon\build\)。
 * 依次试: exe 目录, exe 的上一级, 当前目录。 */
static int find_viewer(char* out, size_t cap)
{
    char dir[MAX_PATH];
    GetModuleFileNameA(NULL, dir, MAX_PATH);
    char* slash = strrchr(dir, '\\');
    if (slash) *slash = 0;

    const char* cands[3];
    char up[MAX_PATH + 64];
    snprintf(up, sizeof up, "%s\\..\\viewer.html", dir);
    char same[MAX_PATH + 64];
    snprintf(same, sizeof same, "%s\\viewer.html", dir);

    cands[0] = up;
    cands[1] = same;
    cands[2] = "viewer.html";

    for (int i = 0; i < 3; i++) {
        DWORD a = GetFileAttributesA(cands[i]);
        if (a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY)) {
            /* 取绝对路径, 免得后续 fopen 受工作目录影响 */
            if (GetFullPathNameA(cands[i], (DWORD)cap, out, NULL)) return 0;
        }
    }
    return -1;
}

/* ---------------- JSON 生成(格式与 tools/dbjson.c 一致) ---------------- */
static const char* METRICS[8] = { "hcho","tvoc","eco2","temp","humi","aqi","eco","thi" };

/* from/to 为 0 表示不限 */
static int build_json(buf_t* out, long long from, long long to, int limit_raw)
{
    char dbp[MAX_PATH];
    db_path_a(dbp, sizeof dbp);

    sqlite3* db = NULL;
    if (sqlite3_open_v2(dbp, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return -1;
    }

    buf_addf(out, "{\n");

    {
        time_t t = time(NULL);
        struct tm tm;
        char ts[64];
        localtime_s(&tm, &t);
        strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", &tm);
        buf_addf(out, "\"generated\":\"%s\",\n", ts);
    }

    /* ---- raw ----
     *
     * limit_raw > 0 时**必须取最新的 N 条**, 不能取最旧的 N 条:
     * 数据攒到 2 万条以后, 取最旧的会导致页面永远只显示很早以前的数据,
     * 新数据怎么都刷不出来(而且看不出来是截断, 只像是"卡住了")。
     * 做法: 内层 DESC + LIMIT 取最新 N 条, 外层再 ASC 还原时间顺序。 */
    buf_addf(out, "\"raw\":[");
    {
        sqlite3_stmt* st = NULL;
        char sql[512];
        if (limit_raw > 0 && !from && !to) {
            snprintf(sql, sizeof sql,
                     "SELECT ts,hcho,tvoc,eco2,temp,humi,aqi,eco,thi FROM ("
                     "  SELECT ts,hcho,tvoc,eco2,temp,humi,aqi,eco,thi FROM raw"
                     "  ORDER BY ts DESC LIMIT %d"
                     ") ORDER BY ts", limit_raw);
        } else {
            snprintf(sql, sizeof sql,
                     "SELECT ts,hcho,tvoc,eco2,temp,humi,aqi,eco,thi FROM raw"
                     " WHERE (?1=0 OR ts>=?1) AND (?2=0 OR ts<=?2) ORDER BY ts");
        }
        int first = 1;
        if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
            if (limit_raw <= 0 || from || to) {
                sqlite3_bind_int64(st, 1, from);
                sqlite3_bind_int64(st, 2, to);
            }
            while (sqlite3_step(st) == SQLITE_ROW) {
                if (!first) buf_addf(out, ",");
                first = 0;
                buf_addf(out, "[%lld,%d,%d,%d,%d,%d,%d,%d,%d]",
                         (long long)sqlite3_column_int64(st, 0),
                         sqlite3_column_int(st, 1), sqlite3_column_int(st, 2),
                         sqlite3_column_int(st, 3), sqlite3_column_int(st, 4),
                         sqlite3_column_int(st, 5), sqlite3_column_int(st, 6),
                         sqlite3_column_int(st, 7), sqlite3_column_int(st, 8));
            }
            sqlite3_finalize(st);
        }
    }
    buf_addf(out, "],\n");

    /* ---- minute ---- */
    buf_addf(out, "\"minute\":[");
    {
        sqlite3_stmt* st = NULL;
        char sql[1024];
        int n = snprintf(sql, sizeof sql, "SELECT ts");
        for (int i = 0; i < 8; i++)
            n += snprintf(sql + n, sizeof sql - n, ",%s_mn,%s_av,%s_mx",
                          METRICS[i], METRICS[i], METRICS[i]);
        snprintf(sql + n, sizeof sql - n,
                 " FROM minute WHERE (?1=0 OR ts>=?1) AND (?2=0 OR ts<=?2) ORDER BY ts");

        int first = 1;
        if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(st, 1, from);
            sqlite3_bind_int64(st, 2, to);
            while (sqlite3_step(st) == SQLITE_ROW) {
                if (!first) buf_addf(out, ",");
                first = 0;
                buf_addf(out, "[%lld", (long long)sqlite3_column_int64(st, 0));
                for (int c = 1; c <= 24; c++)
                    buf_addf(out, ",%.1f", sqlite3_column_double(st, c));
                buf_addf(out, "]");
            }
            sqlite3_finalize(st);
        }
    }
    buf_addf(out, "]\n}\n");

    sqlite3_close(db);
    return 0;
}

/* ---------------- 发送 ---------------- */
static void send_all(SOCKET s, const char* p, size_t len)
{
    size_t off = 0;
    while (off < len) {
        int n = send(s, p + off, (int)(len - off), 0);
        if (n <= 0) break;
        off += (size_t)n;
    }
}

static void send_headers(SOCKET s, const char* status, const char* ctype, size_t len)
{
    char h[512];
    /* 注意: MinGW 链的是 msvcrt 的 printf, 不认 %zu —— 必须用 %llu */
    int n = snprintf(h, sizeof h,
                     "HTTP/1.1 %s\r\n"
                     "Content-Type: %s\r\n"
                     "Content-Length: %llu\r\n"
                     "Cache-Control: no-store, no-cache, must-revalidate\r\n"
                     "Connection: close\r\n"
                     "\r\n",
                     status, ctype, (unsigned long long)len);
    if (n > 0) send_all(s, h, (size_t)n);
}

/* 从查询串取整型参数: "from=123&to=456" */
static long long qs_ll(const char* qs, const char* key)
{
    if (!qs) return 0;
    size_t kl = strlen(key);
    const char* p = qs;
    while (p && *p) {
        if (strncmp(p, key, kl) == 0 && p[kl] == '=') return _strtoi64(p + kl + 1, NULL, 10);
        p = strchr(p, '&');
        if (p) p++;
    }
    return 0;
}

/* ---------------- 单请求处理 ---------------- */
static void handle_conn(SOCKET s)
{
    char req[HTTPD_MAX_REQ];
    int  got = 0;

    /* 读到 \r\n\r\n 或者读满为止 */
    for (;;) {
        if (got >= (int)sizeof req - 1) break;
        int n = recv(s, req + got, (int)sizeof req - 1 - got, 0);
        if (n <= 0) break;
        got += n;
        req[got] = 0;
        if (strstr(req, "\r\n\r\n")) break;
    }
    if (got <= 0) return;
    req[got] = 0;

    /* 只接受 GET */
    if (strncmp(req, "GET ", 4) != 0) {
        const char* body = "method not allowed";
        send_headers(s, "405 Method Not Allowed", "text/plain; charset=utf-8", strlen(body));
        send_all(s, body, strlen(body));
        return;
    }

    char path[512] = {0};
    {
        const char* p = req + 4;
        const char* sp = strchr(p, ' ');
        size_t len = sp ? (size_t)(sp - p) : strlen(p);
        if (len >= sizeof path) len = sizeof path - 1;
        memcpy(path, p, len);
        path[len] = 0;
    }

    /* 拆出查询串 */
    char* qs = strchr(path, '?');
    if (qs) { *qs = 0; qs++; }

    if (strcmp(path, "/api/data") == 0) {
        long long from = qs_ll(qs, "from");
        long long to   = qs_ll(qs, "to");
        /* 没给范围时限制返回量, 避免一次吐出几十万行把浏览器卡死 */
        int limit = (from || to) ? 0 : 20000;

        buf_t out;
        buf_init(&out);
        if (build_json(&out, from, to, limit) != 0 || !out.p) {
            buf_free(&out);
            const char* body = "{\"error\":\"db\"}";
            send_headers(s, "500 Internal Server Error", "application/json", strlen(body));
            send_all(s, body, strlen(body));
            return;
        }
        send_headers(s, "200 OK", "application/json; charset=utf-8", out.len);
        send_all(s, out.p, out.len);
        buf_free(&out);
        return;
    }

    if (strcmp(path, "/") == 0 || strcmp(path, "/viewer.html") == 0 ||
        strcmp(path, "/index.html") == 0) {
        char vp[MAX_PATH];
        if (find_viewer(vp, sizeof vp) != 0) {
            const char* body = "viewer.html not found next to airmon.exe";
            send_headers(s, "404 Not Found", "text/plain; charset=utf-8", strlen(body));
            send_all(s, body, strlen(body));
            return;
        }
        FILE* f = fopen(vp, "rb");
        if (!f) {
            const char* body = "cannot open viewer.html";
            send_headers(s, "500 Internal Server Error", "text/plain; charset=utf-8", strlen(body));
            send_all(s, body, strlen(body));
            return;
        }
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (sz < 0) sz = 0;
        char* mem = (char*)malloc((size_t)sz + 1);
        if (!mem) { fclose(f); return; }
        size_t rd = fread(mem, 1, (size_t)sz, f);
        fclose(f);
        send_headers(s, "200 OK", "text/html; charset=utf-8", rd);
        send_all(s, mem, rd);
        free(mem);
        return;
    }

    /* 其余一律 404(不做目录遍历) */
    {
        const char* body = "not found";
        send_headers(s, "404 Not Found", "text/plain; charset=utf-8", strlen(body));
        send_all(s, body, strlen(body));
    }
}

/* ---------------- 监听线程 ---------------- */
static DWORD WINAPI httpd_thread(LPVOID p)
{
    (void)p;

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        air_log("HTTP: WSAStartup 失败");
        return 1;
    }

    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ls == INVALID_SOCKET) {
        air_log("HTTP: socket 创建失败 (%d)", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    BOOL yes = TRUE;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof yes);

    SOCKADDR_IN sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((u_short)g_httpd_port);
    sa.sin_addr.s_addr = inet_addr("127.0.0.1");   /* 只监听本机 */

    if (bind(ls, (SOCKADDR*)&sa, sizeof sa) == SOCKET_ERROR) {
        air_log("HTTP: bind 127.0.0.1:%d 失败 (%d) — 端口可能被占用",
                g_httpd_port, WSAGetLastError());
        closesocket(ls);
        WSACleanup();
        return 1;
    }
    if (listen(ls, 8) == SOCKET_ERROR) {
        air_log("HTTP: listen 失败 (%d)", WSAGetLastError());
        closesocket(ls);
        WSACleanup();
        return 1;
    }

    air_log("HTTP: 数据网页已就绪 http://127.0.0.1:%d/", g_httpd_port);

    while (InterlockedCompareExchange(&g_httpd_run, 0, 0)) {
        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(ls, &rf);
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int r = select(0, &rf, NULL, NULL, &tv);
        if (r <= 0) continue;
        if (!FD_ISSET(ls, &rf)) continue;

        SOCKET cs = accept(ls, NULL, NULL);
        if (cs == INVALID_SOCKET) continue;
        /* 单线程串行处理: 本机自用, 请求量极小, 省掉线程池的复杂度 */
        handle_conn(cs);
        closesocket(cs);
    }

    closesocket(ls);
    WSACleanup();
    air_log("HTTP: 已停止");
    return 0;
}

void httpd_start(int port)
{
    if (port > 0) g_httpd_port = port;
    if (InterlockedExchange(&g_httpd_run, 1)) return;   /* 已经在跑 */
    CreateThread(NULL, 0, httpd_thread, NULL, 0, NULL);
}

void httpd_stop(void)
{
    InterlockedExchange(&g_httpd_run, 0);
}

int httpd_port(void) { return g_httpd_port; }
