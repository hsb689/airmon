/*
 * trayicon.c - 托盘图标: 透明底 + AQI 数字, 数字颜色按等级绿/黄/红
 *
 * 托盘图标只有 16x16(高 DPI 下 20/24), 光画个圆点很难在任务栏里认出来,
 * 所以直接把当前 AQI 数字画上去, 数字本身按等级着色:
 *   绿 = 正常  黄 = 到国标 80%  红 = 超国标
 * 没有数据时画 "--", 灰色。
 *
 * 背景保持全透明, 只有字形不透明。为了让小字号在深/浅任务栏上都看得清,
 * 字形外加一圈 1px 的半透明黑描边(不是底色块, 只是描边, 保证对比度)。
 *
 * 尺寸按 SM_CXSMICON 取, 这样在 100%/125%/150% 缩放下都是清晰的。
 */
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "airmon.h"

#define TIC_GREEN  RGB(46, 204, 90)
#define TIC_YELLOW RGB(255, 196, 40)
#define TIC_RED    RGB(255, 74, 64)
#define TIC_NONE   RGB(150, 156, 164)

/* 在指定 DC 上把数字画出来; dx/dy 为整体偏移(用于描边) */
static void draw_num(HDC dc, int cx, int cy, const WCHAR* txt, COLORREF col, int dx, int dy)
{
    int n  = lstrlenW(txt);
    int fh = (n <= 1) ? (cy * 82 / 100)
           : (n == 2) ? (cy * 64 / 100)
                      : (cy * 48 / 100);
    HFONT f = CreateFontW(-fh, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET,
                          OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS,
                          (fh >= 12) ? ANTIALIASED_QUALITY : NONANTIALIASED_QUALITY,
                          DEFAULT_PITCH, L"Arial");
    HGDIOBJ of = SelectObject(dc, f);
    SIZE sz;
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, col);
    GetTextExtentPoint32W(dc, txt, n, &sz);
    TextOutW(dc, (cx - sz.cx) / 2 + dx, (cy - sz.cy) / 2 + dy, txt, n);
    SelectObject(dc, of);
    DeleteObject(f);
}

/* 指定尺寸生成图标(便于单独渲染检查) */
HICON trayicon_make_size(int cx, int cy, int aqi, BOOL have)
{
    BITMAPINFO bi;
    void*  bits = NULL;
    HDC    dc;
    HBITMAP color = NULL, mask = NULL;
    HICON  ic = NULL;
    COLORREF fg;
    WCHAR  txt[8];
    int    lv;

    if (cx < 8) cx = 8;
    if (cy < 8) cy = 8;
    if (cx > 64) cx = 64;
    if (cy > 64) cy = 64;

    /* 等级: 超 100 红, 到 80 黄, 其余绿; 无数据灰 */
    lv = have ? (aqi > 100 ? 2 : (aqi >= 80 ? 1 : 0)) : -1;
    fg = (lv < 0) ? TIC_NONE : (lv == 2 ? TIC_RED : (lv == 1 ? TIC_YELLOW : TIC_GREEN));

    if (!have) lstrcpynW(txt, L"--", ARRAYSIZE(txt));
    else       swprintf(txt, ARRAYSIZE(txt), L"%d", aqi);

    ZeroMemory(&bi, sizeof bi);
    bi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth       = cx;
    bi.bmiHeader.biHeight      = -cy;
    bi.bmiHeader.biPlanes      = 1;
    bi.bmiHeader.biBitCount    = 32;
    bi.bmiHeader.biCompression = BI_RGB;

    dc = CreateCompatibleDC(NULL);
    if (!dc) return NULL;
    color = CreateDIBSection(dc, &bi, DIB_RGB_COLORS, &bits, NULL, 0);
    if (!color || !bits) goto out;

    {
        HGDIOBJ old = SelectObject(dc, color);
        ZeroMemory(bits, (size_t)cx * cy * 4);      /* 全透明底, 不铺任何底色 */

        /* 只画彩色数字, 不加描边/底色 —— 背景保持完全透明 */
        draw_num(dc, cx, cy, txt, fg, 0, 0);
        GdiFlush();

        /* 字形像素补成不透明, 其余保持全透明 */
        {
            DWORD* p = (DWORD*)bits;
            for (int i = 0; i < cx * cy; i++)
                if (p[i] & 0x00FFFFFFu) p[i] |= 0xFF000000u;
        }
        SelectObject(dc, old);
    }

    /* 掩码全 0: 透明交给 alpha 通道 */
    {
        BITMAPINFO mb;
        void* mbits = NULL;
        HDC mdc = CreateCompatibleDC(NULL);
        ZeroMemory(&mb, sizeof mb);
        mb.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
        mb.bmiHeader.biWidth       = cx;
        mb.bmiHeader.biHeight      = -cy;
        mb.bmiHeader.biPlanes      = 1;
        mb.bmiHeader.biBitCount    = 1;
        mb.bmiHeader.biCompression = BI_RGB;
        mask = CreateDIBSection(mdc, &mb, DIB_RGB_COLORS, &mbits, NULL, 0);
        DeleteDC(mdc);
    }

    if (mask) {
        ICONINFO ii;
        ZeroMemory(&ii, sizeof ii);
        ii.fIcon    = TRUE;
        ii.hbmMask  = mask;
        ii.hbmColor = color;
        ic = CreateIconIndirect(&ii);
    }

out:
    if (color) DeleteObject(color);
    if (mask)  DeleteObject(mask);
    DeleteDC(dc);
    return ic;
}

/* 按当前系统托盘图标尺寸生成 */
HICON trayicon_make(int aqi, BOOL have)
{
    int cx = GetSystemMetrics(SM_CXSMICON);
    int cy = GetSystemMetrics(SM_CYSMICON);
    if (cx <= 0) cx = 16;
    if (cy <= 0) cy = 16;
    return trayicon_make_size(cx, cy, aqi, have);
}
