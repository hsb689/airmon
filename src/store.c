/*
 * store.c - SQLite 存储 + 分层降采样
 *
 * 表结构:
 *   raw(ts INTEGER PRIMARY KEY, hcho, tvoc, eco2, temp, humi, aqi, eco, thi)
 *       ts=unix 秒; 保留 24h, 每小时清理
 *   minute(ts INTEGER PRIMARY KEY, hcho_mn, hcho_av, hcho_mx, ... x8 字段)
 *       保留 30 天
 *   hour(ts INTEGER PRIMARY KEY, 同 minute 结构) 保留 1 年
 *
 * 写入路径: ble_feed(任意线程) 只更新快照; store_tick(UI 1s 定时器) 取快照
 * 原始入库, 并喂给分钟/小时聚合器, 边界翻转时落一条聚合行。
 */
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "airmon.h"
#include "../third_party/sqlite3.h"

static sqlite3* g_db = NULL;
static CRITICAL_SECTION g_cs;
static BOOL g_cs_init = FALSE;
static air_data_t g_cur;           /* 最新一帧 */
static BOOL g_have = FALSE;

/* 聚合器: 8 项指标的 min/avg(累加)/max。
 * 用 int 而不是 WORD: 温度和 THI 是有符号的, 零下必须是负数,
 * 用无符号会把 -5℃(-500) 存成 65036, 曲线和聚合全错。 */
typedef struct {
    int mn[8], mx[8];
    double sum[8];
    int n;
    long long bucket;   /* 该桶起始 unix 秒 */
} agg_t;

static agg_t g_min_agg;
static long long g_last_gc = 0;

static const char* DDL =
    "PRAGMA journal_mode=WAL;"
    "PRAGMA synchronous=NORMAL;"
    "CREATE TABLE IF NOT EXISTS raw(ts INTEGER PRIMARY KEY,"
        "hcho INTEGER, tvoc INTEGER, eco2 INTEGER, temp INTEGER,"
        "humi INTEGER, aqi INTEGER, eco INTEGER, thi INTEGER);"
    "CREATE TABLE IF NOT EXISTS minute(ts INTEGER PRIMARY KEY,"
        "hcho_mn INTEGER, hcho_av REAL, hcho_mx INTEGER,"
        "tvoc_mn INTEGER, tvoc_av REAL, tvoc_mx INTEGER,"
        "eco2_mn INTEGER, eco2_av REAL, eco2_mx INTEGER,"
        "temp_mn INTEGER, temp_av REAL, temp_mx INTEGER,"
        "humi_mn INTEGER, humi_av REAL, humi_mx INTEGER,"
        "aqi_mn INTEGER, aqi_av REAL, aqi_mx INTEGER,"
        "eco_mn INTEGER, eco_av REAL, eco_mx INTEGER,"
        "thi_mn INTEGER, thi_av REAL, thi_mx INTEGER);"
    "CREATE TABLE IF NOT EXISTS hour(ts INTEGER PRIMARY KEY,"
        "hcho_mn INTEGER, hcho_av REAL, hcho_mx INTEGER,"
        "tvoc_mn INTEGER, tvoc_av REAL, tvoc_mx INTEGER,"
        "eco2_mn INTEGER, eco2_av REAL, eco2_mx INTEGER,"
        "temp_mn INTEGER, temp_av REAL, temp_mx INTEGER,"
        "humi_mn INTEGER, humi_av REAL, humi_mx INTEGER,"
        "aqi_mn INTEGER, aqi_av REAL, aqi_mx INTEGER,"
        "eco_mn INTEGER, eco_av REAL, eco_mx INTEGER,"
        "thi_mn INTEGER, thi_av REAL, thi_mx INTEGER);";

static void exec_simple(const char* sql)
{
    char* err = NULL;
    sqlite3_exec(g_db, sql, NULL, NULL, &err);
    if (err) sqlite3_free(err);
}

int store_open(void)
{
    InitializeCriticalSection(&g_cs);
    g_cs_init = TRUE;

    char path[MAX_PATH];
    /* 数据库与 exe 同目录 */
    GetModuleFileNameA(NULL, path, MAX_PATH);
    char* slash = strrchr(path, '\\');
    if (slash) *(slash + 1) = 0;
    lstrcatA(path, "airmon.db");

    if (sqlite3_open(path, &g_db) != SQLITE_OK) return -1;
    exec_simple(DDL);
    return 0;
}

void store_close(void)
{
    if (g_db) { sqlite3_close(g_db); g_db = NULL; }
    if (g_cs_init) DeleteCriticalSection(&g_cs);
    g_cs_init = FALSE;
}

void ble_feed(const air_data_t* d)
{
    if (!g_cs_init) return;
    EnterCriticalSection(&g_cs);
    g_cur = *d;
    g_have = TRUE;
    LeaveCriticalSection(&g_cs);
}

static const char* AGG_INSERT =
    "INSERT OR REPLACE INTO %s VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,"
    "?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25);";

/* 落一条聚合行 */
static void agg_flush(agg_t* a, const char* table)
{
    if (!g_db || a->n == 0) { memset(a, 0, sizeof *a); return; }
    sqlite3_stmt* st = NULL;
    char sql[256];
    snprintf(sql, sizeof sql, AGG_INSERT, table);
    if (sqlite3_prepare_v2(g_db, sql, -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st, 1, a->bucket);
        for (int i = 0; i < 8; i++) {
            sqlite3_bind_int(st, 2 + i * 3, a->mn[i]);
            sqlite3_bind_double(st, 3 + i * 3, a->sum[i] / a->n);
            sqlite3_bind_int(st, 4 + i * 3, a->mx[i]);
        }
        sqlite3_step(st);
        sqlite3_finalize(st);
    }
    memset(a, 0, sizeof *a);
}

/* 保留策略: raw>24h / minute>30d / hour>1y 清理, 每小时跑一次 */
static void gc(time_t now)
{
    if (now - g_last_gc < 3600) return;
    g_last_gc = now;
    char sql[160];
    snprintf(sql, sizeof sql, "DELETE FROM raw WHERE ts < %lld;", (long long)now - 86400);
    exec_simple(sql);
    snprintf(sql, sizeof sql, "DELETE FROM minute WHERE ts < %lld;", (long long)now - 30LL * 86400);
    exec_simple(sql);
    snprintf(sql, sizeof sql, "DELETE FROM hour WHERE ts < %lld;", (long long)now - 365LL * 86400);
    exec_simple(sql);
}

void store_tick(void)
{
    air_data_t snap;
    if (!g_cs_init || !g_db) return;
    EnterCriticalSection(&g_cs);
    snap = g_cur;
    BOOL have = g_have;
    LeaveCriticalSection(&g_cs);
    if (!have) return;

    time_t now = (time_t)snap.ft.dwLowDateTime |
                 ((time_t)snap.ft.dwHighDateTime << 32);
    /* FILETIME -> unix 秒 (11644473600s 偏移) */
    now = now / 10000000LL - 11644473600LL;

    /* int 而非 WORD: temp_c / thi 是 short, 赋给 int 会自动符号扩展,
     * 零下温度(-500 = -5.00℃)才能正确入库和聚合。 */
    int v[8];
    v[0]=snap.hcho; v[1]=snap.tvoc; v[2]=snap.eco2; v[3]=snap.temp_c;
    v[4]=snap.humi; v[5]=snap.aqi;  v[6]=snap.eco;  v[7]=snap.thi;

    /* raw 1s 直插 */
    sqlite3_stmt* st = NULL;
    if (sqlite3_prepare_v2(g_db,
            "INSERT OR REPLACE INTO raw VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9);",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st, 1, (long long)now);
        for (int i = 0; i < 8; i++) sqlite3_bind_int(st, 2 + i, v[i]);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }

    /* 聚合器: 桶翻转时先落上一桶。
     * 只做分钟级聚合 —— 一年视图已经去掉, 小时表不再写入(表和历史数据保留,
     * 只是不再使用, 以后要恢复随时可以接回来)。 */
    long long min_bucket = now / 60 * 60;
    if (g_min_agg.n && min_bucket != g_min_agg.bucket) agg_flush(&g_min_agg, "minute");

    {
        agg_t* a = &g_min_agg;
        if (a->n == 0) {
            a->bucket = min_bucket;
            for (int i = 0; i < 8; i++) { a->mn[i] = v[i]; a->mx[i] = v[i]; a->sum[i] = v[i]; }
            a->n = 1;
        } else {
            for (int i = 0; i < 8; i++) {
                if (v[i] < a->mn[i]) a->mn[i] = v[i];
                if (v[i] > a->mx[i]) a->mx[i] = v[i];
                a->sum[i] += v[i];
            }
            a->n++;
        }
    }

    gc(now);
}

/* ---- 查询: 取指定范围的历史点, 供 UI 画曲线 ---- */
/* 范围改成最小 5 分钟; 1 年那一档已去掉(不再提供一年视图) */
#define RANGE_5M  0
#define RANGE_1H  1
#define RANGE_5H  2
#define RANGE_7D  3
#define RANGE_1MO 4

static series_t g_series;
static int g_cur_range = 0;

/* 选层: 5min/1h/5h -> raw(抽稀), 7d/1mo -> minute */
static void query_layer(int range, int metric, time_t now)
{
    g_series.n = 0;
    g_series.metric = metric;
    if (!g_db) return;

    const char* table;
    long long span;
    switch (range) {
    case RANGE_5M:  table = "raw";    span = 300; break;
    case RANGE_1H:  table = "raw";    span = 3600; break;
    case RANGE_5H:  table = "raw";    span = 5 * 3600; break;
    case RANGE_7D:  table = "minute"; span = 7LL * 86400; break;
    default:        table = "minute"; span = 30LL * 86400; break;   /* 1 个月 */
    }
    g_series.span = (double)span;   /* 横轴固定用窗口长度, 见下面的扫描式说明 */

    char col[8];
    const char* names[] = { "hcho", "tvoc", "eco2", "temp", "humi", "aqi", "eco", "thi" };
    snprintf(col, sizeof col, "%s", names[metric]);

    /* ---- 滚动窗口 ----
     * 取"最近 span 秒"的点, 横坐标 = 点相对窗口左端的秒数(0..span)。
     * 窗口右端始终是"现在", 于是每来一帧:
     *   最旧的点从左边挤出去 -> 其余整体左移 -> 新点从右边进来。
     *
     * 打开程序时这里会直接把数据库里已有的历史点全部取出来, 所以曲线不是从 0
     * 开始慢慢长, 而是一打开就显示这段时间的真实数据, 然后继续往左滚。
     *
     * 注意: 横轴分母固定用 span(存在 g_series.span 里), 不能用数据自身跨度,
     * 否则数据一变整条曲线就重新缩放, 看起来在乱跳。 */

    /* ---- 没有新数据时冻住横轴 ----
     * 断开连接后如果还让窗口跟着"现在"往前滑, 已有数据会被一路推出左边界,
     * 最后整块图变成空白 —— 用户看到的就是"图还在走, 但里面什么都没有"。
     * 所以窗口右端取 min(现在, 最后一条数据 + 宽限):
     *   - 正常接收(每 5 秒一帧): 现在 ≈ 最后数据, 曲线平滑滚动
     *   - 断开超过 60 秒: 右端钉在"最后数据+60秒", 图停住, 数据留在画面里 */
    long long right = (long long)now;
    {
        char msql[128];
        sqlite3_stmt* mst = NULL;
        snprintf(msql, sizeof msql, "SELECT MAX(ts) FROM %s;", table);
        if (sqlite3_prepare_v2(g_db, msql, -1, &mst, NULL) == SQLITE_OK) {
            if (sqlite3_step(mst) == SQLITE_ROW && sqlite3_column_type(mst, 0) != SQLITE_NULL) {
                long long last = sqlite3_column_int64(mst, 0);
                if (last > 0 && right > last + 60) right = last + 60;
            }
            sqlite3_finalize(mst);
        }
    }
    long long from = right - span;

    char sql[512];
    if (strcmp(table, "raw") == 0)
        snprintf(sql, sizeof sql,
            "SELECT ts, %s, %s, %s FROM raw WHERE ts >= %lld ORDER BY ts;",
            col, col, col, from);
    else
        snprintf(sql, sizeof sql,
            "SELECT ts, %s_mn, %s_av, %s_mx FROM %s WHERE ts >= %lld ORDER BY ts;",
            col, col, col, table, from);

    sqlite3_stmt* st = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &st, NULL) != SQLITE_OK) return;

    /* 点太多时按步长抽稀到 MAX_POINTS 以内 */
    long long cnt = 0;
    while (sqlite3_step(st) == SQLITE_ROW) cnt++;
    sqlite3_reset(st);
    long long stride = cnt > MAX_POINTS ? (cnt + MAX_POINTS - 1) / MAX_POINTS : 1;

    long long idx = 0;
    while (sqlite3_step(st) == SQLITE_ROW && g_series.n < MAX_POINTS) {
        if (idx++ % stride) continue;
        long long ts = sqlite3_column_int64(st, 0);

        double mn = sqlite3_column_double(st, 1);
        double av = sqlite3_column_double(st, 2);
        double mx = sqlite3_column_double(st, 3);
        /* 温度/湿度/eCO/THI 是定点放大值, 除回真实量纲 */
        double scale = (metric == 3 || metric == 4) ? 100.0 : (metric == 6 ? 10.0 : (metric == 7 ? 10.0 : 1.0));
        g_series.ts[g_series.n] = (double)(ts - from);   /* 0..span, 右端=最新 */
        g_series.mn[g_series.n] = mn / scale;
        g_series.av[g_series.n] = av / scale;
        g_series.mx[g_series.n] = mx / scale;
        g_series.n++;
    }
    sqlite3_finalize(st);
}

void store_query_range(int range_id)
{
    time_t now = (time_t)time(NULL);
    g_cur_range = range_id;
    query_layer(range_id, g_series.metric, now);
}

void store_get_last(air_data_t* out)
{
    EnterCriticalSection(&g_cs);
    *out = g_cur;
    LeaveCriticalSection(&g_cs);
}

void store_set_metric(int metric)
{
    if (metric < 0 || metric > 7) metric = 0;
    time_t now = (time_t)time(NULL);
    query_layer(g_cur_range, metric, now);
}

void store_get_series(series_t* out)
{
    EnterCriticalSection(&g_cs);
    *out = g_series;
    LeaveCriticalSection(&g_cs);
}

const char* store_metric_name(int metric)
{
    static const char* names[] = { "HCHO", "TVOC", "eCO2", "TEMP", "HUMI", "AQI", "eCO", "THI" };
    if (metric < 0 || metric > 7) return names[0];
    return names[metric];
}
