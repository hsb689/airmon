/*
 * ui.c - 半透明黑色悬浮窗 (分层窗口) 绘制 + 拖拽 + 连接按钮 + 右键菜单
 *
 * 布局(320x268):
 *   顶部: 标题 + 连接/断开按钮
 *   状态: 状态点 + 一行状态文案
 *   中部: 8 项指标网格 (甲醛/总挥发性有机物/二氧化碳/温度/湿度/空气质量/一氧化碳/热指数)
 *   底部: 当前选择范围的历史曲线缩略图
 *
 * 背景不是纯黑: UpdateLayeredWindow 逐像素 alpha, 底板 alpha=180/255 的"透明黑",
 * 文字/曲线按亮度补到接近不透明, 所以底板透出桌面而文字清晰。
 *
 * 圆角全部走有符号距离场(SDF)算覆盖度, 1px 抗锯齿;
 * 底板形状由 apply_alpha 统一裁切, 按钮/曲线框在 paint 里直接写像素做 AA。
 */
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <windowsx.h>
#include <shellapi.h>
#include <stdio.h>
#include <math.h>
#include "airmon.h"

extern air_data_t g_last;   /* 每帧绘制前从 store 取最新快照 */
#define REFRESH_LAST() store_get_last(&g_last)

#define PANEL_ALPHA  180     /* 底板不透明度 180/255 ≈ 70% */
#define PANEL_RADIUS 14.f
#define BTN_RADIUS   9.f
#define BOX_RADIUS   8.f

static int  g_range = 0;     /* 0=5分钟 1=1小时 2=5小时 3=7天 4=1个月 */
static int  g_metric = 0;    /* 0..7 曲线指标 */

/* 点「断开」后的短暂视觉反馈(纯界面, 完全不碰 gatt 状态机)。
 * 底层收尾(关 CCCD + Close 服务 + Close 设备)实测 2~13 秒, 这期间状态可能
 * 一直是 CONN_OK, 按钮看着像没反应 —— 点下去先让按钮变灰显示"断开中" 1.5 秒。 */
static ULONGLONG g_btn_flash_until = 0;
static int  g_ble_note = 0;  /* ble.c 回报: 2=监听启动失败 3=本机没有蓝牙适配器 */
static BOOL g_topmost = TRUE;

/* 拖拽状态 */
static BOOL  g_drag = FALSE;
static BOOL  g_btn_down = FALSE;
static POINT g_drag_cursor;
static POINT g_drag_org;

static const WCHAR* RANGE_NAMES[] = { L"5分钟", L"1小时", L"5小时", L"7天", L"1个月" };

/* 指标名: 中文在前, 英文缩写放括号里 */
static const WCHAR* LABELS[] = {
    L"甲醛 (HCHO)",
    L"总挥发性有机物 (TVOC)",
    L"二氧化碳 (eCO2)",
    L"温度",
    L"湿度",
    L"空气质量 (AQI)",
    L"一氧化碳 (eCO)",
    L"热指数 (THI)",
};

/* 曲线框左上角空间小, 用短名 */
static const WCHAR* LABELS_SHORT[] = {
    L"HCHO", L"TVOC", L"eCO2", L"温度", L"湿度", L"AQI", L"eCO", L"THI",
};

/* 字体缓存(进程内复用, 不释放) */
static HFONT g_f_title, g_f_label, g_f_value, g_f_unit, g_f_status, g_f_btn, g_f_small;

static void ensure_fonts(void)
{
    if (g_f_value) return;
    #define MK(px, bold) CreateFontW((px), 0, 0, 0, (bold) ? FW_SEMIBOLD : FW_NORMAL, \
        0, 0, 0, DEFAULT_CHARSET, OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS, \
        ANTIALIASED_QUALITY, DEFAULT_PITCH, L"Microsoft YaHei UI")
    g_f_title  = MK(18, 1);   /* 标题放大: 15 太小, 中文挤在一起 */
    g_f_label  = MK(11, 0);
    g_f_value  = MK(24, 1);   /* 数值放大: 原来 20, 远看更清楚 */
    g_f_unit   = MK(10, 0);
    g_f_status = MK(12, 0);
    g_f_btn    = MK(12, 1);
    g_f_small  = MK(11, 0);
    #undef MK
}

static RECT btn_rect(void)
{
    RECT r = { AIRMON_W - 12 - 58, 7, AIRMON_W - 12, 29 };
    return r;
}

static RECT curve_rect(void)
{
    RECT r = { 10, 220, AIRMON_W - 10, AIRMON_H - 10 };
    return r;
}

/* ---------------- 等级配色 (统一绿/黄/红) ----------------
 * 绿 #3fb950  黄 #d29922  红 #f85149
 * 判定: 到国标 80% 转黄, 超国标转红; THI/湿度按各自区间表。 */
#define COL_GREEN  RGB(63, 185, 80)
#define COL_YELLOW RGB(210, 153, 34)
#define COL_RED    RGB(248, 81, 73)
#define COL_NODATA RGB(120, 128, 138)

/* GB/T 18883-2022 室内空气质量标准 */
#define GB_HCHO  80.0    /* µg/m³  = 0.08 mg/m³ */
#define GB_TVOC  600.0   /* µg/m³  = 0.60 mg/m³ */
#define GB_ECO2  1000.0  /* ppm    = 0.10 %   */
#define GB_CO_MG 10.0    /* mg/m³  (eCO 报的是 ppm, 按 1ppm≈1.25mg/m³ 换算) */
#define GB_AQI   100.0   /* AQI 100 为"良"的上限 */
#define CO_PPM_TO_MG 1.25

/* 等级: 0=绿 1=黄 2=红 -1=无数据 */
static COLORREF lv_color(int lv)
{
    if (lv < 0)  return COL_NODATA;
    if (lv >= 2) return COL_RED;
    if (lv == 1) return COL_YELLOW;
    return COL_GREEN;
}

/* 到国标 80% 黄, 超国标红 */
static int lv_by_limit(double v, double limit)
{
    if (v > limit)          return 2;
    if (v >= limit * 0.8)   return 1;
    return 0;
}

/* 湿度: 国标 40~70% 舒适, 30~40 / 70~80 偏差, 更外面算超标 */
static int lv_humi(double h)
{
    if (h < 30.0 || h > 80.0) return 2;
    if (h < 40.0 || h > 70.0) return 1;
    return 0;
}

/* THI 等级: <13 冷(红) 13~18 凉(黄) 18~23 舒适(绿) 23~29 暖(黄) >=29 热(红) */
static int lv_thi(double thi)
{
    if (thi < 13.0) return 2;
    if (thi < 18.0) return 1;
    if (thi < 23.0) return 0;
    if (thi < 29.0) return 1;
    return 2;
}

/* 曲线用的国标限值(单位与序列一致: HCHO/TVOC 是 µg/m³, eCO2/AQI 原值, eCO 是 ppm)。
 * 返回 <=0 表示这个指标没有单一限值(温度/湿度/THI 是区间, 不画线)。 */
static double metric_limit(int m)
{
    switch (m) {
    case 0:  return GB_HCHO;                    /* µg/m³ */
    case 1:  return GB_TVOC;                    /* µg/m³ */
    case 2:  return GB_ECO2;                    /* ppm   */
    case 5:  return GB_AQI;
    case 6:  return GB_CO_MG / CO_PPM_TO_MG;    /* mg/m³ -> ppm */
    default: return -1.0;                       /* 温度/湿度/THI 没有单值国标 */
    }
}

static const WCHAR* thi_word(double thi){
    if (thi < 13.0) return L"冷";
    if (thi < 18.0) return L"凉";
    if (thi < 23.0) return L"舒适";
    if (thi < 29.0) return L"暖";
    return L"热";
}

/* ---------------- 抗锯齿圆角 ---------------- */
static float clampf(float v, float lo, float hi)
{
    return v < lo ? lo : (v > hi ? hi : v);
}

/* 圆角矩形有符号距离: 外部为正, 边界为 0, 内部为负 */
static float rr_sd(float px, float py, float l, float t, float r, float b, float rad)
{
    float cx = (l + r) * 0.5f;
    float cy = (t + b) * 0.5f;
    float hx = (r - l) * 0.5f - 0.5f;
    float hy = (b - t) * 0.5f - 0.5f;
    float qx = fabsf(px - cx) - (hx - rad);
    float qy = fabsf(py - cy) - (hy - rad);
    float mx = qx > 0.f ? qx : 0.f;
    float my = qy > 0.f ? qy : 0.f;
    float m  = qx > qy ? qx : qy;
    return sqrtf(mx * mx + my * my) + (m < 0.f ? m : 0.f) - rad;
}

/* 覆盖度: 边界 0.5, 内部 1, 外部 0, 1px 过渡带 */
static float rr_cov(float px, float py, float l, float t, float r, float b, float rad)
{
    return clampf(0.5f - rr_sd(px, py, l, t, r, b, rad), 0.f, 1.f);
}

/* 直接把抗锯齿圆角矩形填进 DIB (绕过 GDI 的硬边栅格化) */
static void aa_fill_round(DWORD* px, int w, int h, RECT rc, float rad, COLORREF c)
{
    int cr = GetRValue(c), cg = GetGValue(c), cb = GetBValue(c);
    int x0 = rc.left - 1, x1 = rc.right + 1;
    int y0 = rc.top - 1, y1 = rc.bottom + 1;
    if (x0 < 0) x0 = 0;
    if (y0 < 0) y0 = 0;
    if (x1 > w) x1 = w;
    if (y1 > h) y1 = h;

    for (int y = y0; y < y1; y++) {
        for (int x = x0; x < x1; x++) {
            float cov = rr_cov(x + 0.5f, y + 0.5f,
                               (float)rc.left, (float)rc.top,
                               (float)rc.right, (float)rc.bottom, rad);
            if (cov <= 0.f) continue;
            {
                DWORD p = px[y * w + x];
                int dr = (int)(p & 0xFF);
                int dg = (int)((p >> 8) & 0xFF);
                int db = (int)((p >> 16) & 0xFF);
                int nr = dr + (int)((cr - dr) * cov);
                int ng = dg + (int)((cg - dg) * cov);
                int nb = db + (int)((cb - db) * cov);
                px[y * w + x] = (p & 0xFF000000u) |
                                ((DWORD)nb << 16) | ((DWORD)ng << 8) | (DWORD)nr;
            }
        }
    }
}

/* 抗锯齿圆角描边(约 1px) */
static void aa_stroke_round(DWORD* px, int w, int h, RECT rc, float rad, COLORREF c)
{
    int cr = GetRValue(c), cg = GetGValue(c), cb = GetBValue(c);
    int x0 = rc.left - 2, x1 = rc.right + 2;
    int y0 = rc.top - 2, y1 = rc.bottom + 2;
    if (x0 < 0) x0 = 0;
    if (y0 < 0) y0 = 0;
    if (x1 > w) x1 = w;
    if (y1 > h) y1 = h;

    for (int y = y0; y < y1; y++) {
        for (int x = x0; x < x1; x++) {
            float sd  = rr_sd(x + 0.5f, y + 0.5f,
                              (float)rc.left, (float)rc.top,
                              (float)rc.right, (float)rc.bottom, rad);
            float cov = clampf(0.6f - fabsf(sd), 0.f, 1.f);
            if (cov <= 0.f) continue;
            {
                DWORD p = px[y * w + x];
                int dr = (int)(p & 0xFF);
                int dg = (int)((p >> 8) & 0xFF);
                int db = (int)((p >> 16) & 0xFF);
                int nr = dr + (int)((cr - dr) * cov);
                int ng = dg + (int)((cg - dg) * cov);
                int nb = db + (int)((cb - db) * cov);
                px[y * w + x] = (p & 0xFF000000u) |
                                ((DWORD)nb << 16) | ((DWORD)ng << 8) | (DWORD)nr;
            }
        }
    }
}

/* ---------------- 文字/数值 ---------------- */
static void draw_text(HDC dc, HFONT f, COLORREF c, int x, int y, const WCHAR* s)
{
    HGDIOBJ of = SelectObject(dc, f);
    SetTextColor(dc, c);
    TextOutW(dc, x, y, s, lstrlenW(s));
    SelectObject(dc, of);
}

static void draw_text_right(HDC dc, HFONT f, COLORREF c, int right, int y, const WCHAR* s)
{
    HGDIOBJ of = SelectObject(dc, f);
    SIZE sz;
    SetTextColor(dc, c);
    GetTextExtentPoint32W(dc, s, lstrlenW(s), &sz);
    TextOutW(dc, right - sz.cx, y, s, lstrlenW(s));
    SelectObject(dc, of);
}

/* 数值格式化: 没数据就显示 "--" */
static const WCHAR* num(WCHAR* buf, BOOL have, const WCHAR* fmt, double v)
{
    if (!have) { lstrcpynW(buf, L"--", 32); return buf; }
    swprintf(buf, 32, fmt, v);
    return buf;
}

static void draw_metric(HDC dc, int x, int y, int idx,
                        const WCHAR* val, const WCHAR* unit, int lv)
{
    draw_text(dc, g_f_label, RGB(138, 146, 156), x, y, LABELS[idx]);
    draw_text(dc, g_f_value, lv_color(lv), x, y + 13, val);
    if (unit && unit[0]) {
        /* 单位紧跟在数值右边。数值字号放大了, 用固定偏移会重叠,
         * 所以量一下实际宽度再定位。 */
        HGDIOBJ of = SelectObject(dc, g_f_value);
        SIZE sz = {0, 0};
        GetTextExtentPoint32W(dc, val, lstrlenW(val), &sz);
        SelectObject(dc, of);
        draw_text(dc, g_f_unit, RGB(118, 126, 136), x + sz.cx + 5, y + 21, unit);
    }
}

/* 历史曲线: 淡色填充 min-max 包络, 亮色画 avg 线 */
static void draw_series(HDC dc, const RECT* rc)
{
    series_t s;
    store_get_series(&s);
    if (s.n < 2) return;

    int x0 = rc->left + 2, x1 = rc->right - 2;
    int y0 = rc->top + 14, y1 = rc->bottom - 2;
    /* 横轴固定用该范围的时间窗长度, 不按数据自身跨度缩放。
     * 配合 store.c 的滚动窗口: 最旧的点从左边挤出去、其余左移、新点从右边进来,
     * 一直滚, 不清空重画。以前分母取"最后一个点的偏移", 数据一变整条线就重新缩放,
     * 看起来在乱跳。 */
    double span = s.span > 0 ? s.span : (s.ts[s.n - 1] > 0 ? s.ts[s.n - 1] : 1);

    double lo = 1e18, hi = -1e18;
    for (int i = 0; i < s.n; i++) {
        if (s.mn[i] < lo) lo = s.mn[i];
        if (s.mx[i] > hi) hi = s.mx[i];
    }

    /* 国标限值线: 让用户一眼看出"这段时间有没有超标"。
     * 限值也要算进纵轴范围, 否则数据远低于限值时那条线会跑到框外面看不见。 */
    double lim = metric_limit(s.metric & 7);
    if (lim > 0 && lim > hi) hi = lim;

    if (hi - lo < 1e-6) { hi += 1; lo -= 1; }
    double pad = (hi - lo) * 0.1;
    lo -= pad; hi += pad;

    #define SX(t)  (int)(x0 + (t) / span * (x1 - x0))
    #define SY(v)  (int)(y1 - ((v) - lo) / (hi - lo) * (y1 - y0))

    /* min-max 包络填充 */
    HPEN env_pen = CreatePen(PS_SOLID, 1, RGB(40, 90, 60));
    HBRUSH env_br = CreateSolidBrush(RGB(20, 50, 35));
    HPEN oep = (HPEN)SelectObject(dc, env_pen);
    HBRUSH ob = (HBRUSH)SelectObject(dc, env_br);
    for (int i = 0; i < s.n - 1; i++) {
        POINT p[4] = {
            { SX(s.ts[i]),   SY(s.mn[i]) },
            { SX(s.ts[i+1]), SY(s.mn[i+1]) },
            { SX(s.ts[i+1]), SY(s.mx[i+1]) },
            { SX(s.ts[i]),   SY(s.mx[i]) },
        };
        Polygon(dc, p, 4);
    }
    SelectObject(dc, oep); SelectObject(dc, ob);
    DeleteObject(env_pen); DeleteObject(env_br);

    /* avg 折线 */
    HPEN av_pen = CreatePen(PS_SOLID, 1, RGB(80, 220, 140));
    HPEN oap = (HPEN)SelectObject(dc, av_pen);
    for (int i = 0; i < s.n - 1; i++) {
        MoveToEx(dc, SX(s.ts[i]), SY(s.av[i]), NULL);
        LineTo(dc, SX(s.ts[i+1]), SY(s.av[i+1]));
    }
    SelectObject(dc, oap);
    DeleteObject(av_pen);

    /* 国标限值线: 虚线, 超过它就是超标(只画线, 不写字) */
    if (lim > 0 && lim >= lo && lim <= hi) {
        int yl = SY(lim);
        HPEN lp = CreatePen(PS_DOT, 1, RGB(120, 210, 150));
        HPEN olp = SelectObject(dc, lp);
        MoveToEx(dc, x0, yl, NULL);
        LineTo(dc, x1, yl);
        SelectObject(dc, olp);
        DeleteObject(lp);
    }

    /* 纵轴上下限: 没有刻度值就看不出曲线在什么量级 */
    {
        WCHAR yb[32];
        swprintf(yb, ARRAYSIZE(yb), L"%.0f", hi);
        draw_text(dc, g_f_small, RGB(118, 126, 136), x0 + 1, y0 - 1, yb);
        swprintf(yb, ARRAYSIZE(yb), L"%.0f", lo);
        draw_text(dc, g_f_small, RGB(118, 126, 136), x0 + 1, y1 - 12, yb);
    }

    draw_text(dc, g_f_small, RGB(110, 180, 130), rc->left + 4, rc->top + 1,
              LABELS_SHORT[s.metric & 7]);
}

static void draw_button(HDC dc)
{
    RECT r = btn_rect();
    COLORREF fg;
    const WCHAR* label;
    int st = 0;

    gatt_status(NULL, 0, &st);
    if (st == CONN_OK) {
        fg = RGB(255, 228, 228); label = L"断开";
    } else if (st == CONN_SCAN || st == CONN_LINK) {
        fg = RGB(222, 228, 234); label = L"取消";
    } else {
        fg = RGB(240, 255, 244); label = L"连接";
    }
    /* 点了「断开」之后的短暂视觉反馈: 只改显示, 不动 gatt 状态机 */
    if (GetTickCount64() < g_btn_flash_until) {
        fg = RGB(200, 206, 214); label = L"断开中";
    }

    {
        HGDIOBJ of = SelectObject(dc, g_f_btn);
        SIZE sz;
        SetTextColor(dc, fg);
        GetTextExtentPoint32W(dc, label, lstrlenW(label), &sz);
        TextOutW(dc, r.left + (r.right - r.left - sz.cx) / 2,
                     r.top + (r.bottom - r.top - sz.cy) / 2, label, lstrlenW(label));
        SelectObject(dc, of);
    }
}

static void draw_status(HDC dc)
{
    WCHAR txt[160] = {0};
    int st = 0;
    COLORREF dotc;

    gatt_status(txt, ARRAYSIZE(txt), &st);

    switch (st) {
    case CONN_OK:   dotc = COL_GREEN;  break;
    case CONN_SCAN:
    case CONN_LINK: dotc = COL_YELLOW; break;
    case CONN_FAIL: dotc = COL_RED;    break;
    default:        dotc = RGB(96, 102, 110); break;
    }

    /* 点了「断开」: 先给个"正在断开…"的反馈(纯界面, 不影响底层) */
    if (GetTickCount64() < g_btn_flash_until) {
        lstrcpynW(txt, L"正在断开…", ARRAYSIZE(txt));
        dotc = COL_YELLOW;
    }

    /* 已连上但超过 6 秒没新帧 */
    if (st == CONN_OK) {
        FILETIME now;
        ULARGE_INTEGER a, b;
        GetSystemTimeAsFileTime(&now);
        a.LowPart  = g_last.ft.dwLowDateTime;
        a.HighPart = g_last.ft.dwHighDateTime;
        b.LowPart  = now.dwLowDateTime;
        b.HighPart = now.dwHighDateTime;
        if (a.QuadPart && b.QuadPart > a.QuadPart &&
            (b.QuadPart - a.QuadPart) > 60000000ULL) {
            lstrcpynW(txt, L"已连接 · 6 秒没收到数据 (检查传感器)", ARRAYSIZE(txt));
            dotc = RGB(212, 172, 60);
        }
    } else if (st == CONN_IDLE && g_ble_note == 3) {
        lstrcpynW(txt, L"本机没有蓝牙适配器 — 台式机通常需外接 USB 蓝牙", ARRAYSIZE(txt));
        dotc = COL_RED;
    } else if (st == CONN_IDLE && g_ble_note == 2) {
        lstrcpynW(txt, L"蓝牙广播监听启动失败 (需 Win10 1809+ / 蓝牙已开)", ARRAYSIZE(txt));
        dotc = COL_RED;
    }

    {
        HBRUSH br = CreateSolidBrush(dotc);
        HGDIOBJ ob = SelectObject(dc, br);
        HGDIOBJ op = SelectObject(dc, GetStockObject(NULL_PEN));
        Ellipse(dc, 12, 38, 20, 46);
        SelectObject(dc, ob);
        SelectObject(dc, op);
        DeleteObject(br);
    }
    draw_text(dc, g_f_status, RGB(196, 204, 214), 26, 33, txt);
}

static void paint(HDC dc, DWORD* px, int w, int h)
{
    RECT full  = { 0, 0, w, h };
    RECT br    = btn_rect();
    RECT cb    = curve_rect();
    BOOL have  = g_last.ft.dwLowDateTime || g_last.ft.dwHighDateTime;
    WCHAR b1[32];
    COLORREF btnc;
    int st = 0;

    ensure_fonts();
    SetBkMode(dc, TRANSPARENT);

    /* ---- 形状: 直接写像素做抗锯齿 (先画形状, 再用 GDI 写字) ---- */
    /* 底板描边 (底板本体由 apply_alpha 裁切) */
    aa_stroke_round(px, w, h, full, PANEL_RADIUS, RGB(64, 71, 82));

    /* 连接按钮 */
    gatt_status(NULL, 0, &st);
    if (st == CONN_OK)                          btnc = RGB(122, 40, 44);
    else if (st == CONN_SCAN || st == CONN_LINK) btnc = RGB(58, 64, 72);
    else                                        btnc = RGB(34, 120, 60);
    if (GetTickCount64() < g_btn_flash_until)   btnc = RGB(58, 64, 72);
    aa_fill_round(px, w, h, br, BTN_RADIUS, btnc);

    /* 曲线框 */
    aa_stroke_round(px, w, h, cb, BOX_RADIUS, RGB(52, 58, 66));

    GdiFlush();   /* 形状是直接写 DIB 的, 之后 GDI 画之前先刷一次 */

    /* ---- 文字 ---- */
    draw_text(dc, g_f_title, RGB(228, 234, 242), 12, 5, L"桌面空气监测站");
    draw_button(dc);
    draw_status(dc);

    /* 指标网格 2 列 x 4 行 —— 数值颜色统一按等级(绿/黄/红) */
    {
        double t   = g_last.temp_c / 100.0;
        double hh  = g_last.humi / 100.0;
        double eco = g_last.eco / 10.0;
        double thi = g_last.thi / 10.0;

        int lv_hcho = have ? lv_by_limit((double)g_last.hcho, GB_HCHO) : -1;
        int lv_tvoc = have ? lv_by_limit((double)g_last.tvoc, GB_TVOC) : -1;
        int lv_eco2 = have ? lv_by_limit((double)g_last.eco2, GB_ECO2) : -1;
        int lv_temp = have ? lv_thi(thi) : -1;          /* 温度跟随 THI 等级 */
        int lv_hum  = have ? lv_humi(hh) : -1;
        int lv_aqi  = have ? lv_by_limit((double)g_last.aqi, GB_AQI) : -1;
        int lv_co   = have ? lv_by_limit(eco * CO_PPM_TO_MG, GB_CO_MG) : -1;
        int lv_th   = have ? lv_thi(thi) : -1;

        /* 第 1 行: 湿度 / 温度 */
        draw_metric(dc, 14, 58, 4, num(b1, have, L"%.2f", hh), L"%RH", lv_hum);
        draw_metric(dc, 170, 58, 3, num(b1, have, L"%.2f", t), L"\x2103", lv_temp);
        /* 第 2 行: 二氧化碳 / 一氧化碳 */
        draw_metric(dc, 14, 98, 2, num(b1, have, L"%.0f", g_last.eco2), L"ppm", lv_eco2);
        draw_metric(dc, 170, 98, 6, num(b1, have, L"%.1f", eco), L"ppm", lv_co);
        /* 第 3 行: 空气质量 / 总挥发性有机物 */
        draw_metric(dc, 14, 138, 5, num(b1, have, L"%.0f", g_last.aqi), L"", lv_aqi);
        draw_metric(dc, 170, 138, 1, num(b1, have, L"%.0f", g_last.tvoc), L"ug/m3", lv_tvoc);
        /* 第 4 行: 甲醛 / 热指数 */
        draw_metric(dc, 14, 178, 0, num(b1, have, L"%.0f", g_last.hcho), L"ug/m3", lv_hcho);
        draw_metric(dc, 170, 178, 7, num(b1, have, L"%.1f", thi), L"", lv_th);

        /* THI 中文等级 (冷/凉/舒适/暖/热) */
        if (have)
            draw_text(dc, g_f_status, lv_color(lv_th), 228, 197, thi_word(thi));
    }

    /* 曲线区文字 */
    draw_series(dc, &cb);
    draw_text_right(dc, g_f_small, RGB(140, 148, 158), cb.right - 6, cb.top + 1,
                    RANGE_NAMES[g_range]);
}

/* 逐像素 alpha: 底板半透明, 亮像素(文字/曲线)接近不透明; 圆角按覆盖度抗锯齿 */
static void apply_alpha(DWORD* px, int w, int h)
{
    for (int y = 0; y < h; y++) {
        for (int x = 0; x < w; x++) {
            float cov = rr_cov(x + 0.5f, y + 0.5f, 0.f, 0.f,
                               (float)w, (float)h, PANEL_RADIUS);
            if (cov <= 0.f) { px[y * w + x] = 0; continue; }

            {
                DWORD p = px[y * w + x];
                int r = (int)(p & 0xFF);
                int g = (int)((p >> 8) & 0xFF);
                int b = (int)((p >> 16) & 0xFF);
                int lum = r > g ? r : g;
                int a;
                if (b > lum) lum = b;
                /* rgb 已是"按覆盖率预乘"的值, 这里补 alpha 并按边缘覆盖度缩放 */
                a = PANEL_ALPHA + (255 - PANEL_ALPHA) * lum / 255;
                a = (int)(a * cov);
                r = (int)(r * cov);
                g = (int)(g * cov);
                b = (int)(b * cov);
                px[y * w + x] = ((DWORD)a << 24) | ((DWORD)b << 16) |
                                ((DWORD)g << 8) | (DWORD)r;
            }
        }
    }
}

/* 重新查询当前范围的历史序列。
 *
 * 之前只在"启动"和"切换范围/指标"时查一次, 新数据到了也不重查 ——
 * 于是曲线是冻住的, 只有数字在动, 看起来就像"数据更新很慢"。
 * 设备 5 秒一帧, 曲线就该每 5 秒往前推一格。 */
void ui_refresh_series(void)
{
    static ULONGLONG last = 0;
    ULONGLONG now = GetTickCount64();
    /* 节流: 最多每秒查一次。5 小时范围要扫上万行 raw, 每帧都查会拖慢界面。 */
    if (now - last < 900) return;
    last = now;
    store_query_range(g_range);
}

void ui_render(HWND hwnd)
{
    static HDC     s_mem  = NULL;
    static HBITMAP s_bmp  = NULL;
    static void*   s_bits = NULL;

    REFRESH_LAST();

    if (!s_mem) {
        BITMAPINFO bi;
        HDC screen = GetDC(NULL);
        ZeroMemory(&bi, sizeof bi);
        bi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
        bi.bmiHeader.biWidth       = AIRMON_W;
        bi.bmiHeader.biHeight      = -AIRMON_H;   /* top-down */
        bi.bmiHeader.biPlanes      = 1;
        bi.bmiHeader.biBitCount    = 32;
        bi.bmiHeader.biCompression = BI_RGB;
        s_mem  = CreateCompatibleDC(screen);
        s_bmp  = CreateDIBSection(screen, &bi, DIB_RGB_COLORS, &s_bits, NULL, 0);
        ReleaseDC(NULL, screen);
        if (!s_mem || !s_bmp || !s_bits) return;
        SelectObject(s_mem, s_bmp);
    }

    /* 底板先铺成面板色, 形状交给 apply_alpha */
    {
        DWORD* p = (DWORD*)s_bits;
        DWORD bg = (DWORD)((16u << 16) | (12u << 8) | 10u);   /* RGB(10,12,16) */
        for (int i = 0; i < AIRMON_W * AIRMON_H; i++) p[i] = bg;
    }

    paint(s_mem, (DWORD*)s_bits, AIRMON_W, AIRMON_H);
    GdiFlush();
    apply_alpha((DWORD*)s_bits, AIRMON_W, AIRMON_H);

    {
        RECT wr;
        POINT dst, src = { 0, 0 };
        SIZE sz = { AIRMON_W, AIRMON_H };
        BLENDFUNCTION bf;
        HDC screen;

        GetWindowRect(hwnd, &wr);
        dst.x = wr.left;
        dst.y = wr.top;
        bf.BlendOp             = AC_SRC_OVER;
        bf.BlendFlags          = 0;
        bf.SourceConstantAlpha = 255;
        bf.AlphaFormat         = AC_SRC_ALPHA;

        screen = GetDC(NULL);
        UpdateLayeredWindow(hwnd, screen, &dst, &sz, s_mem, &src, 0, &bf, ULW_ALPHA);
        ReleaseDC(NULL, screen);
    }
}

void ui_init(HWND hwnd)
{
    g_topmost = GetPrivateProfileIntW(L"win", L"topmost", 1, air_cfg_path()) ? TRUE : FALSE;
    SetWindowPos(hwnd, g_topmost ? HWND_TOPMOST : HWND_NOTOPMOST, 0, 0, 0, 0,
                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);

    /* 恢复上次选的曲线指标和历史范围。这里只读值, 不查库 —— 此时 store_open()
     * 还没调用, 查了也是空的。真正的查询由 main.c 里的 ui_restore_view() 做。 */
    g_range  = GetPrivateProfileIntW(L"view", L"range",  0, air_cfg_path());
    g_metric = GetPrivateProfileIntW(L"view", L"metric", 0, air_cfg_path());
    if (g_range  < 0 || g_range  > 4) g_range  = 0;
    if (g_metric < 0 || g_metric > 7) g_metric = 0;
}

/* 把当前范围/指标写进配置, 下次启动沿用 */
static void save_view(void)
{
    WCHAR buf[16];
    swprintf(buf, ARRAYSIZE(buf), L"%d", g_range);
    WritePrivateProfileStringW(L"view", L"range", buf, air_cfg_path());
    swprintf(buf, ARRAYSIZE(buf), L"%d", g_metric);
    WritePrivateProfileStringW(L"view", L"metric", buf, air_cfg_path());
}

/* 启动时按上次保存的范围/指标查一次, 让曲线区立刻有内容。
 * 必须在 store_open() 之后调用。 */
void ui_restore_view(void)
{
    store_query_range(g_range);   /* 先定范围(此时指标还是默认) */
    store_set_metric(g_metric);   /* 再按保存的指标重查一次 */
}

void ui_note_ble(int code)
{
    g_ble_note = code;
}

static void save_pos(HWND hwnd)
{
    RECT wr;
    WCHAR buf[16];
    GetWindowRect(hwnd, &wr);
    swprintf(buf, ARRAYSIZE(buf), L"%d", (int)wr.left);
    WritePrivateProfileStringW(L"win", L"x", buf, air_cfg_path());
    swprintf(buf, ARRAYSIZE(buf), L"%d", (int)wr.top);
    WritePrivateProfileStringW(L"win", L"y", buf, air_cfg_path());
}

/* 点按钮: 未连接->连接, 连接中->取消, 已连接->断开 */
static void on_button(void)
{
    int st = 0;
    gatt_status(NULL, 0, &st);
    if (st == CONN_OK || st == CONN_SCAN || st == CONN_LINK) {
        /* 底层收尾要 2~13 秒, 期间状态可能还是 CONN_OK, 看着像没反应。
         * 这里只做 UI 反馈(1.5 秒), 断开逻辑本身保持原样。 */
        g_btn_flash_until = GetTickCount64() + 1500;
        gatt_disconnect();
    } else {
        gatt_connect_async();
    }
}

int ui_mouse(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    (void)wp;
    switch (msg) {
    case WM_LBUTTONDOWN: {
        POINT pt = { GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
        RECT br = btn_rect();
        if (PtInRect(&br, pt)) { g_btn_down = TRUE; return 1; }

        /* 其它位置: 按住拖动窗口。
           锚点用消息里的客户区坐标换算到屏幕坐标 —— 等价于 GetCursorPos,
           但不受输入注入限制。 */
        g_drag = TRUE;
        ClientToScreen(hwnd, &pt);
        g_drag_cursor = pt;
        {
            RECT wr;
            GetWindowRect(hwnd, &wr);
            g_drag_org.x = wr.left;
            g_drag_org.y = wr.top;
        }
        SetCapture(hwnd);
        return 1;
    }

    case WM_MOUSEMOVE:
        if (g_drag) {
            POINT p = { GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
            ClientToScreen(hwnd, &p);
            SetWindowPos(hwnd, NULL,
                         g_drag_org.x + (p.x - g_drag_cursor.x),
                         g_drag_org.y + (p.y - g_drag_cursor.y),
                         0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
            return 1;
        }
        return 0;

    case WM_LBUTTONUP: {
        if (g_drag) {
            g_drag = FALSE;
            ReleaseCapture();
            save_pos(hwnd);
            return 1;
        }
        if (g_btn_down) {
            POINT pt = { GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
            RECT br = btn_rect();
            g_btn_down = FALSE;
            if (PtInRect(&br, pt)) { on_button(); InvalidateRect(hwnd, NULL, FALSE); }
            return 1;
        }
        return 0;
    }

    case WM_RBUTTONUP:
        ui_tray_menu(hwnd);
        return 1;

    case WM_CAPTURECHANGED:
        g_drag = FALSE;
        return 0;
    }
    return 0;
}

void ui_tray_menu(HWND hwnd)
{
    HMENU m;
    HMENU sub, sub2;
    int st = 0;
    POINT pt;
    int cmd;
    LONG_PTR ex_old;

    /* 防重入 + 防连发。
     * 托盘右键在部分系统上会连发 WM_RBUTTONUP 和 WM_CONTEXTMENU, 两个都
     * 进到这里时, 第二个菜单会在第一个菜单的模态循环里被打开, 表现就是
     * "菜单闪一下就消失了"。 */
    {
        static ULONGLONG last_show = 0;
        ULONGLONG now = GetTickCount64();
        if (now - last_show < 400) return;
        last_show = now;
    }

    m = CreatePopupMenu();
    if (!m) return;

    gatt_status(NULL, 0, &st);

    AppendMenuW(m, MF_STRING, 100, L"显示/隐藏");
    AppendMenuW(m, MF_STRING | (g_topmost ? MF_CHECKED : 0), 402, L"窗口置顶 (总在最前)");
    {
        /* 提示实际可用的快捷键, 免得藏起来后不知道怎么找回来 */
        const WCHAR* hk = air_hotkey_name();
        WCHAR hint[64];
        if (hk && hk[0]) swprintf(hint, ARRAYSIZE(hint), L"快捷键: %s 显示/隐藏", hk);
        else lstrcpynW(hint, L"快捷键: 无 (已被其它程序占用)", ARRAYSIZE(hint));
        AppendMenuW(m, MF_STRING | MF_GRAYED, 403, hint);
    }
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_STRING | (st == CONN_OK ? MF_GRAYED : 0), 400, L"连接设备");
    AppendMenuW(m, MF_STRING | (st == CONN_OK ? 0 : MF_GRAYED), 401, L"断开连接");
    AppendMenuW(m, MF_STRING, 405, L"重启蓝牙服务 (搜不到设备时用, 需管理员)");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);

    sub = CreatePopupMenu();
    for (int i = 0; i < 5; i++)
        AppendMenuW(sub, MF_STRING | (i == g_range ? MF_CHECKED : 0), 200 + i, RANGE_NAMES[i]);
    AppendMenuW(m, MF_POPUP, (UINT_PTR)sub, L"历史范围");

    sub2 = CreatePopupMenu();
    for (int i = 0; i < 8; i++)
        AppendMenuW(sub2, MF_STRING | (i == g_metric ? MF_CHECKED : 0), 300 + i, LABELS[i]);
    AppendMenuW(m, MF_POPUP, (UINT_PTR)sub2, L"曲线指标");

    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_STRING, 299, L"退出");

    GetCursorPos(&pt);

    /* 关键: 主窗口是 WS_EX_NOACTIVATE 的分层窗口, 它永远无法成为前台窗口,
     * 而 TrackPopupMenu 要求 owner 窗口是前台 —— 否则菜单拿不到鼠标捕获,
     * 一有输入就被系统关掉, 表现就是"菜单弹出来一下瞬间消失"。
     * 提权运行后 SetForegroundWindow 更容易失败, 所以这里临时去掉
     * WS_EX_NOACTIVATE, 显示完菜单再恢复。 */
    ex_old = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
    SetWindowLongPtrW(hwnd, GWL_EXSTYLE, ex_old & ~(LONG_PTR)WS_EX_NOACTIVATE);
    SetWindowPos(hwnd, NULL, 0, 0, 0, 0,
                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
    SetForegroundWindow(hwnd);

    cmd = TrackPopupMenu(m, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);

    /* 微软推荐做法: 菜单关闭后给自己补一个空消息, 否则菜单可能残留/抢焦点 */
    PostMessageW(hwnd, WM_NULL, 0, 0);
    SetWindowLongPtrW(hwnd, GWL_EXSTYLE, ex_old);
    DestroyMenu(m);

    if (cmd == 100) {
        air_toggle_visible();       /* 里面会检查托盘/热键是否可用, 防止藏了就找不回来 */
    } else if (cmd == 402) {
        g_topmost = !g_topmost;
        SetWindowPos(hwnd, g_topmost ? HWND_TOPMOST : HWND_NOTOPMOST, 0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        WritePrivateProfileStringW(L"win", L"topmost", g_topmost ? L"1" : L"0",
                                   air_cfg_path());
    } else if (cmd == 400) {
        gatt_connect_async();
        InvalidateRect(hwnd, NULL, FALSE);
    } else if (cmd == 401) {
        gatt_disconnect();
        InvalidateRect(hwnd, NULL, FALSE);
    } else if (cmd == 405) {
        /* 重启 bthserv: 等于"关一次蓝牙再打开", 清掉系统级占用 */
        if (air_restart_bt_service()) {
            MessageBoxW(hwnd,
                L"蓝牙服务已重启。\n等 3~5 秒后设备会重新开始广播, 手机应该就能搜到了。",
                L"AirMon", MB_ICONINFORMATION);
            /* 监听器会在几秒后自动重建, 这里强制刷新一次界面 */
            InvalidateRect(hwnd, NULL, FALSE);
        } else {
            MessageBoxW(hwnd,
                L"重启蓝牙服务失败：需要管理员权限。\n\n"
                L"这个功能只在设备被系统占用、搜不到时才用得到。要用的话：\n"
                L"  1. 退出本程序\n"
                L"  2. 右键 airmon.exe → 「以管理员身份运行」\n"
                L"  3. 再点这个菜单项\n\n"
                L"或者不用它，直接手动关一次蓝牙再打开：\n"
                L"设置 → 蓝牙和其他设备 → 关闭蓝牙 → 等 3 秒 → 再打开。",
                L"AirMon", MB_ICONWARNING);
        }
    } else if (cmd == 299) {
        DestroyWindow(hwnd);
    } else if (cmd >= 200 && cmd <= 204) {
        g_range = cmd - 200;
        store_query_range(g_range);
        save_view();                    /* 记住, 下次启动沿用 */
        InvalidateRect(hwnd, NULL, FALSE);
    } else if (cmd >= 300 && cmd <= 307) {
        g_metric = cmd - 300;
        store_set_metric(g_metric);
        save_view();                    /* 记住, 下次启动沿用 */
        InvalidateRect(hwnd, NULL, FALSE);
    }
}
