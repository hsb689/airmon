#pragma once
/* airmon 公共定义 */

#include <windows.h>

#define AIRMON_W 300
#define AIRMON_H 268

#define WM_APP_DATA (WM_APP + 2)   /* BLE/GATT 线程 -> UI: 新数据到达 */
#define WM_APP_BLE  (WM_APP + 3)   /* BLE 线程 -> UI: 状态(1=started 2=failed 3=对时成功) */
#define WM_APP_GATT (WM_APP + 4)   /* GATT 线程 -> UI: 连接状态变化, wParam = conn_state_t */

/* 广播 Manufacturer Data (公司 ID 0xFFFF) / 传感特征通知 (16 字节) 布局,
 * 全部小端 u16, 共 8 项 16 字节。
 *
 * 注意: 温度和 THI 是**有符号**的(固件用 (uint16) 强转补码发送),
 * 零下时最高位为 1 —— 必须用 short 解析, 用 WORD 会得到 65000 多。
 * 其余字段都是无符号正数, 用 WORD。 */
typedef struct {
    WORD  hcho;     /* µg/m³      */
    WORD  tvoc;     /* µg/m³      */
    WORD  eco2;     /* ppm        */
    short temp_c;   /* ×0.01 ℃   (有符号, 零下为补码) */
    WORD  humi;     /* ×0.01 %RH  */
    WORD  aqi;      /* 1          */
    WORD  eco;      /* ×0.1 ppm   */
    short thi;      /* ×0.1       (有符号) */
    FILETIME ft;    /* 收到时间   */
} air_data_t;

/* store.c — SQLite 存储 */
int  store_open(void);
void store_close(void);
void store_tick(void);                    /* 1s 节拍: 原始入库 + 降采样聚合 */
void store_query_range(int range_id);     /* 0=1h 1=5h 2=7d 3=1mo 4=1y */

/* 历史序列(单指标 min/avg/max), ui.c 画曲线用 */
#define MAX_POINTS 1024
typedef struct {
    double ts[MAX_POINTS];    /* 相对秒, 0..span */
    double mn[MAX_POINTS], av[MAX_POINTS], mx[MAX_POINTS];
    int n;
    int metric;               /* 0..7 */
    double span;              /* 该范围的时间窗长度(秒), 横轴固定用它, 不再按数据缩放 */
} series_t;

void store_set_metric(int metric);        /* 切换曲线指标并重查 */
void store_get_series(series_t* out);     /* 拷贝当前序列 */
const char* store_metric_name(int metric);
void store_get_last(air_data_t* out);     /* 最新一帧快照 */

/* ble.c — 广播监听 + 对时 */
int  ble_start(HWND notify_wnd);
void ble_stop(void);
void ble_feed(const air_data_t* d);   /* 收到数据, store.c 实现 */
UINT64 ble_get_addr(void);            /* 最近一次广播里的设备地址, 0=尚未发现 */
void ble_clear_addr(void);            /* 断开/失败后清缓存, 让下次「连接」重新扫描 */
int  ble_seen_within(DWORD ms);       /* 最近 ms 内是否扫到过本设备(自动重连用) */
int  ble_radio_present(void);         /* 本机是否有蓝牙适配器 */

/* 广播扫描统计, 用于解释"为什么扫不到设备" */
typedef struct {
    unsigned total;        /* 收到的广播总数 */
    unsigned named;        /* 其中带设备名的 */
    unsigned have_addr;    /* 是否已认出设备地址 */
    int      watcher_status;/* 监听器状态: 0=Created 1=Started 3=Stopped 4=Aborted 5=Error, -1=未知 */
    WCHAR    last_name[64];/* 最后一次看到的设备名 */
} ble_stats_t;
void ble_get_stats(ble_stats_t* out);

/* timesync.c — 对时服务写入 (复用主连接的 service, 不再自己建连) */
void timesync_start(HWND ui);
void timesync_pause(int pause);       /* 用户断开后暂停, 不再去连设备 */
int  timesync_write_on_service(void* svc);   /* 在已建立的 IGattDeviceService 上写对时 */

/* gatt.c — 主动连接 (点「连接」后建立 GATT 链路并订阅传感通知) */
typedef enum {
    CONN_IDLE = 0,      /* 未连接 */
    CONN_SCAN,          /* 正在搜索设备 */
    CONN_LINK,          /* 正在建立连接 / 订阅 */
    CONN_OK,            /* 已连接, 正在接收 */
    CONN_FAIL           /* 失败 / 已断开 */
} conn_state_t;

void gatt_start(HWND ui);
void gatt_stop(void);
void gatt_connect_async(void);                 /* 点「连接」 */
void gatt_disconnect(void);                    /* 点「断开」 */
void gatt_status(WCHAR* text, int cap, int* state);
BOOL gatt_busy(void);                          /* 搜索 / 连接中 */
BOOL gatt_is_connected(void);                  /* 主连接是否已建立(对时用它做闸门) */

/* main.c — 配置(窗口位置、上次设备地址)文件路径 */
const WCHAR* air_cfg_path(void);
void air_toggle_visible(void);        /* 显示/隐藏(带"藏了还能找回"的检查) */
const WCHAR* air_hotkey_name(void);   /* 实际注册到的显示/隐藏热键, 空=没有 */
BOOL air_restart_bt_service(void);    /* 重启 bthserv: 清掉系统级的设备占用 */

/* 系统通知: 连接断开/重连时提示 */
typedef enum {
    AIR_NOTIFY_LOST = 0,        /* 连接意外断开 */
    AIR_NOTIFY_RECONNECTED,     /* 重连成功 */
    AIR_NOTIFY_RECONNECT_FAIL   /* 重连放弃 */
} air_notify_kind_t;

void air_notify(int kind);            /* 任意线程可调, 内部转投到 UI 线程 */

/* notify.c — Toast 优先, 返回 FALSE 表示调用方该用托盘气泡兜底 */
BOOL notify_toast(const WCHAR* title, const WCHAR* body);

/* trayicon.c — 把 AQI 数字画进托盘图标(绿/黄/红底色) */
HICON trayicon_make(int aqi, BOOL have);
HICON trayicon_make_size(int cx, int cy, int aqi, BOOL have);

/* airlog.c — 极简日志(exe 同目录 airmon.log), 用于排查蓝牙问题 */
void air_log(const char* fmt, ...);

/* ui.c — 绘制、拖拽、按钮与菜单 */
void ui_init(HWND hwnd);                                   /* 读配置并应用置顶 */
void ui_render(HWND hwnd);
void ui_refresh_series(void);                              /* 重查历史序列(曲线跟新帧走) */
void ui_restore_view(void);                                /* 启动时恢复上次的范围/指标 */
void ui_tray_menu(HWND hwnd);
int  ui_mouse(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);   /* 1=已处理 */
void ui_note_ble(int code);                                /* ble.c 状态回报 */
