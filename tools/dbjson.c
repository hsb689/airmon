/*
 * dbjson.c - 把 airmon.db 导出成 JSON, 给 viewer.html 用
 *
 * 用法: dbjson.exe [airmon.db] [输出.json]
 *       默认 airmon.db / airmon.json
 *
 * 输出格式(尽量紧凑, 用数组不用对象):
 * {
 *   "generated": "2026-10-28 13:20:00",
 *   "raw":    [[ts, hcho,tvoc,eco2,temp,humi,aqi,eco,thi], ...],
 *   "minute": [[ts, m0mn,m0av,m0mx, m1mn,m1av,m1mx, ...], ...]   // 8 指标 x 3
 * }
 *
 * 注意: 温度/湿度是 x100 存储, eCO/THI 是 x10 存储, 这里原样导出,
 *       由 viewer.html 按同样的比例换算, 和上位机显示保持一致。
 *
 * 以只读方式打开, 程序正在运行也能导出; WAL 里未合并的数据也能读到。
 */
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <time.h>
#include "../third_party/sqlite3.h"

static const char* METRICS[8] = { "hcho","tvoc","eco2","temp","humi","aqi","eco","thi" };

int main(int argc, char** argv)
{
    const char* dbpath = (argc > 1) ? argv[1] : "airmon.db";
    const char* outpath = (argc > 2) ? argv[2] : "airmon.json";
    sqlite3* db = NULL;
    FILE* f = NULL;
    int first;

    if (sqlite3_open_v2(dbpath, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        printf("打开数据库失败: %s\n", db ? sqlite3_errmsg(db) : "?");
        return 1;
    }
    f = fopen(outpath, "wb");
    if (!f) { printf("无法写入 %s\n", outpath); sqlite3_close(db); return 1; }

    fprintf(f, "{\n");

    /* ---- 生成时间 ---- */
    {
        time_t t = time(NULL);
        struct tm tm;
        char ts[64];
        localtime_s(&tm, &t);
        strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", &tm);
        fprintf(f, "\"generated\":\"%s\",\n", ts);
    }

    /* ---- raw ---- */
    fprintf(f, "\"raw\":[");
    {
        sqlite3_stmt* st = NULL;
        const char* sql =
            "SELECT ts,hcho,tvoc,eco2,temp,humi,aqi,eco,thi FROM raw ORDER BY ts;";
        first = 1;
        if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
            while (sqlite3_step(st) == SQLITE_ROW) {
                if (!first) fputc(',', f);
                first = 0;
                fprintf(f, "[%lld,%d,%d,%d,%d,%d,%d,%d,%d]",
                        (long long)sqlite3_column_int64(st, 0),
                        sqlite3_column_int(st, 1), sqlite3_column_int(st, 2),
                        sqlite3_column_int(st, 3), sqlite3_column_int(st, 4),
                        sqlite3_column_int(st, 5), sqlite3_column_int(st, 6),
                        sqlite3_column_int(st, 7), sqlite3_column_int(st, 8));
            }
            sqlite3_finalize(st);
        }
    }
    fprintf(f, "],\n");

    /* ---- minute: 每行 1 个 ts + 8 指标 x (mn,av,mx) ---- */
    fprintf(f, "\"minute\":[");
    {
        sqlite3_stmt* st = NULL;
        char sql[1024];
        int n = snprintf(sql, sizeof sql, "SELECT ts");
        for (int i = 0; i < 8; i++)
            n += snprintf(sql + n, sizeof sql - n, ",%s_mn,%s_av,%s_mx",
                          METRICS[i], METRICS[i], METRICS[i]);
        snprintf(sql + n, sizeof sql - n, " FROM minute ORDER BY ts;");

        first = 1;
        if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
            while (sqlite3_step(st) == SQLITE_ROW) {
                if (!first) fputc(',', f);
                first = 0;
                fprintf(f, "[%lld", (long long)sqlite3_column_int64(st, 0));
                for (int c = 1; c <= 24; c++) {
                    /* av 是 REAL, mn/mx 是 INT; 统一按 double 输出, 保留 1 位小数 */
                    fprintf(f, ",%.1f", sqlite3_column_double(st, c));
                }
                fputc(']', f);
            }
            sqlite3_finalize(st);
        }
    }
    fprintf(f, "]\n}\n");

    fclose(f);
    sqlite3_close(db);
    printf("已导出: %s\n", outpath);
    return 0;
}
