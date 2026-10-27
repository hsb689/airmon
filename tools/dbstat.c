/*
 * dbstat.c - 查询 airmon.db 的内容概况 (只读)
 *
 * 用途: 确认"关掉程序再打开, 历史数据还在不在"。
 * 打印每张表的行数、时间范围, 以及最近几条 raw 记录。
 *
 * 编译: gcc -std=c11 -O2 dbstat.c ../third_party/sqlite3.c -o dbstat.exe
 */
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <time.h>
#include "../third_party/sqlite3.h"

static void show_table(sqlite3* db, const char* table)
{
    char sql[512];
    sqlite3_stmt* st = NULL;
    long long n = 0, mn = 0, mx = 0;

    snprintf(sql, sizeof sql,
             "SELECT COUNT(*), MIN(ts), MAX(ts) FROM %s;", table);
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        printf("  %-8s : 不存在或读失败\n", table);
        return;
    }
    if (sqlite3_step(st) == SQLITE_ROW) {
        n  = sqlite3_column_int64(st, 0);
        mn = sqlite3_column_int64(st, 1);
        mx = sqlite3_column_int64(st, 2);
    }
    sqlite3_finalize(st);

    if (n == 0) {
        printf("  %-8s : 0 行\n", table);
        return;
    }
    {
        time_t t1 = (time_t)mn, t2 = (time_t)mx;
        struct tm a, b;
        char s1[64] = "?", s2[64] = "?";
        localtime_s(&a, &t1);
        localtime_s(&b, &t2);
        strftime(s1, sizeof s1, "%m-%d %H:%M:%S", &a);
        strftime(s2, sizeof s2, "%m-%d %H:%M:%S", &b);
        printf("  %-8s : %lld 行, 从 %s 到 %s\n", table, n, s1, s2);
    }
}

int main(int argc, char** argv)
{
    sqlite3* db = NULL;
    const char* path = (argc > 1) ? argv[1] : "airmon.db";

    printf("数据库: %s\n", path);
    /* 只读打开, 不干扰正在运行的程序 */
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        printf("打开失败: %s\n", db ? sqlite3_errmsg(db) : "?");
        return 1;
    }

    printf("\n各表概况:\n");
    show_table(db, "raw");
    show_table(db, "minute");
    show_table(db, "hour");

    printf("\n最近 5 条 raw (温度/湿度 x100, eCO/THI x10):\n");
    {
        sqlite3_stmt* st = NULL;
        if (sqlite3_prepare_v2(db,
                "SELECT ts,hcho,tvoc,eco2,temp,humi,aqi,eco,thi FROM raw "
                "ORDER BY ts DESC LIMIT 5;", -1, &st, NULL) == SQLITE_OK) {
            while (sqlite3_step(st) == SQLITE_ROW) {
                time_t t = (time_t)sqlite3_column_int64(st, 0);
                struct tm tmv;
                char ts[64];
                localtime_s(&tmv, &t);
                strftime(ts, sizeof ts, "%m-%d %H:%M:%S", &tmv);
                printf("  %s  HCHO=%d TVOC=%d eCO2=%d 温度=%.2f 湿度=%.2f AQI=%d eCO=%.1f THI=%.1f\n",
                       ts,
                       sqlite3_column_int(st, 1), sqlite3_column_int(st, 2),
                       sqlite3_column_int(st, 3),
                       sqlite3_column_int(st, 4) / 100.0,
                       sqlite3_column_int(st, 5) / 100.0,
                       sqlite3_column_int(st, 6),
                       sqlite3_column_int(st, 7) / 10.0,
                       sqlite3_column_int(st, 8) / 10.0);
            }
            sqlite3_finalize(st);
        }
    }

    sqlite3_close(db);
    return 0;
}
