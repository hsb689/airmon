/*
 * gatt.c - 主动连接 PB03F-AIR 并订阅传感器通知 (纯 C, WinRT ABI 直调)
 *
 * ble.c 只能被动收广播。本模块负责"主动连接":
 *   1. BluetoothLEDevice.FromBluetoothAddressAsync(addr)                      槽 7
 *   2. IBluetoothLEDevice3.GetGattServicesForUuidWithCacheModeAsync(svc, Uncached)  槽 11
 *      -> IGattDeviceServicesResult: get_Status 槽 6, get_Services 槽 8
 *   3. IGattDeviceService3.GetCharacteristicsForUuidWithCacheModeAsync(chr, Uncached) 槽 14
 *      -> IGattCharacteristicsResult: get_Status 槽 6, get_Characteristics 槽 8
 *   4. IGattCharacteristic.add_ValueChanged                槽 20  (先挂监听)
 *      IGattCharacteristic.WriteClientCharacteristicConfigurationDescriptorAsync(Notify=1) 槽 19
 *   5. 保活: 每秒读 IBluetoothLEDevice.get_ConnectionStatus 槽 9
 *
 * 槽位取自 windows-0.61.3 crate 的 ABI 定义(本机 MinGW 无 WinRT 头, 只能直调 vtable)。
 * 注意: 带 GUID 参数的方法一律用"类型化函数指针"调用 —— 走可变参数宏时
 * x64 ABI 会把 16 字节结构体按引用传递, GUID 会整个错掉。
 */
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winstring.h>
#include <objbase.h>
#include <roapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "airmon.h"

/* ---------------- 接口 GUID ---------------- */
static const IID IID_IUnknown_v =
    {0x00000000,0x0000,0x0000,{0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}};
static const IID IID_IBluetoothLEDeviceStatics =
    {0xc8cf1a19,0xf0b6,0x4bf0,{0x86,0x89,0x41,0x30,0x3d,0xe2,0xd9,0xf4}};
static const IID IID_IBluetoothLEDevice =
    {0xb5ee2f7b,0x4ad8,0x4642,{0xac,0x48,0x80,0xa0,0xb5,0x00,0xe8,0x87}};
static const IID IID_IBluetoothLEDevice3 =
    {0xaee9e493,0x44ac,0x40dc,{0xaf,0x33,0xb2,0xc1,0x3c,0x01,0xca,0x46}};
static const IID IID_IGattDeviceService =
    {0xac7b7c05,0xb33c,0x47cf,{0x99,0x0f,0x6b,0x8f,0x55,0x77,0xdf,0x71}};
static const IID IID_IGattDeviceService3 =
    {0xb293a950,0x0c53,0x437c,{0xa9,0xb3,0x5c,0x32,0x10,0xc6,0xe5,0x69}};
static const IID IID_IGattCharacteristic =
    {0x59cb50c1,0x5934,0x4f68,{0xa1,0x98,0xeb,0x86,0x4f,0xa4,0x4e,0x6b}};
static const IID IID_IBufferByteAccess =
    {0x905a0fef,0xbc53,0x11df,{0x8c,0x49,0x00,0x1e,0x4f,0xc6,0x86,0xda}};
/* IClosable: 6=Close。GattDeviceService / BluetoothLEDevice 都实现它,
 * 主动 Close 才能真正释放 GATT 资源、断开物理链路。 */
static const IID IID_IClosable =
    {0x30d5a829,0x7fa4,0x4026,{0x83,0xbb,0xd7,0x5b,0xae,0x4e,0xa9,0x9e}};


static const WCHAR CLASS_BLEDEV[] =
    L"Windows.Devices.Bluetooth.BluetoothLEDevice";

/* 固件服务/特征 UUID (标准 128 位, 见 ble_app.c 注释的 5833FFxx 基数) */
static const GUID SVC_AIR    =
    {0x5833FF05,0x9B8B,0x5191,{0x61,0x42,0x22,0xA4,0x53,0x6E,0xF1,0x23}};
static const GUID CHR_SENSOR =
    {0x5833FF07,0x9B8B,0x5191,{0x61,0x42,0x22,0xA4,0x53,0x6E,0xF1,0x23}};

/* BluetoothCacheMode::Uncached —— 强制走真实服务发现, 不吃系统缓存 */
#define CACHE_UNCACHED 1
#define CACHE_CACHED   0   /* BluetoothCacheMode::Cached — 用系统缓存, 秒回 */
/* GattCommunicationStatus::Success */
#define GATT_OK 0
/* GattClientCharacteristicConfigurationDescriptorValue::Notify */
#define CCCD_NOTIFY 1
#define CCCD_NONE   0
/* BluetoothConnectionStatus::Connected */
#define CONN_STATUS_CONNECTED 1

/* ---------------- 类型化槽位调用 ---------------- */
/* 取 vtable 第 slot 槽并转成指定函数指针类型 */
#define VFN(obj, slot, type) ((type)(*(void***)(obj))[(slot)])

typedef HRESULT (STDMETHODCALLTYPE *PFN_QI)(void*, const IID*, void**);
typedef HRESULT (STDMETHODCALLTYPE *PFN_async_status)(void*, INT32*);
typedef HRESULT (STDMETHODCALLTYPE *PFN_async_errcode)(void*, INT32*);
typedef HRESULT (STDMETHODCALLTYPE *PFN_async_cancel)(void*);
typedef HRESULT (STDMETHODCALLTYPE *PFN_async_results)(void*, void**);
typedef HRESULT (STDMETHODCALLTYPE *PFN_get_uint32)(void*, UINT32*);
typedef HRESULT (STDMETHODCALLTYPE *PFN_get_i32)(void*, INT32*);
typedef HRESULT (STDMETHODCALLTYPE *PFN_get_obj)(void*, void**);
typedef HRESULT (STDMETHODCALLTYPE *PFN_get_guid)(void*, GUID*);
typedef HRESULT (STDMETHODCALLTYPE *PFN_vec_getat)(void*, UINT32, void**);
typedef HRESULT (STDMETHODCALLTYPE *PFN_fromdevid)(void*, void*, void**);
typedef HRESULT (STDMETHODCALLTYPE *PFN_from_addr)(void*, UINT64, void**);
typedef HRESULT (STDMETHODCALLTYPE *PFN_svc_sync)(void*, GUID, void**);
typedef HRESULT (STDMETHODCALLTYPE *PFN_svc_uuid_cache)(void*, GUID, INT32, void**);
/* IBluetoothLEDevice3.GetGattServicesWithCacheModeAsync (槽 9): 枚举全部服务 */
typedef HRESULT (STDMETHODCALLTYPE *PFN_svc_cache)(void*, INT32, void**);
typedef HRESULT (STDMETHODCALLTYPE *PFN_chr_sync)(void*, GUID, void**);
typedef HRESULT (STDMETHODCALLTYPE *PFN_chr_uuid_cache)(void*, GUID, INT32, void**);
/* IGattDeviceService3.GetCharacteristicsWithCacheModeAsync (槽 12): 枚举全部特征 */
typedef HRESULT (STDMETHODCALLTYPE *PFN_chr_cache)(void*, INT32, void**);
typedef HRESULT (STDMETHODCALLTYPE *PFN_write_cccd)(void*, INT32, void**);
typedef HRESULT (STDMETHODCALLTYPE *PFN_add_handler)(void*, void*, INT64*);
typedef HRESULT (STDMETHODCALLTYPE *PFN_rm_handler)(void*, INT64);
typedef HRESULT (STDMETHODCALLTYPE *PFN_set_bool)(void*, BOOL);
typedef HRESULT (STDMETHODCALLTYPE *PFN_close)(void*);

static ULONG rel(IUnknown* p) { return p ? p->lpVtbl->Release(p) : 0; }

static HRESULT qi(void* obj, const IID* iid, void** out)
{
    if (!obj) { if (out) *out = NULL; return E_POINTER; }
    return ((IUnknown*)obj)->lpVtbl->QueryInterface((IUnknown*)obj, iid, out);
}

/* IBuffer -> 原始字节 */
typedef struct IBufferByteAccessVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IUnknown*, const IID*, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IUnknown*);
    ULONG   (STDMETHODCALLTYPE *Release)(IUnknown*);
    HRESULT (STDMETHODCALLTYPE *Buffer)(IUnknown*, BYTE**);
} IBufferByteAccessVtbl;
typedef struct IBufferByteAccess { IBufferByteAccessVtbl* lpVtbl; } IBufferByteAccess;

/* 读 IBuffer 内容, 返回实际字节数 */
static UINT32 buf_bytes(void* buf, BYTE* out, UINT32 cap)
{
    UINT32 len = 0;
    IBufferByteAccess* bba = NULL;
    if (!buf) return 0;
    VFN(buf, 7, PFN_get_uint32)(buf, &len);
    if (!len) return 0;
    if (FAILED(((IUnknown*)buf)->lpVtbl->QueryInterface((IUnknown*)buf,
                &IID_IBufferByteAccess, (void**)&bba)) || !bba) return 0;
    {
        BYTE* p = NULL;
        if (SUCCEEDED(bba->lpVtbl->Buffer((IUnknown*)bba, &p)) && p) {
            UINT32 n = len < cap ? len : cap;
            memcpy(out, p, n);
            len = n;
        } else len = 0;
    }
    bba->lpVtbl->Release((IUnknown*)bba);
    return len;
}

/* ---------------- 状态 ---------------- */
/* 这些要放在 await_async 之前: 那个函数靠 g_quit 判断进程正在退出 */
static HWND g_ui = NULL;
static HANDLE g_evt = NULL;
static HANDLE g_thread = NULL;
static CRITICAL_SECTION g_lock;
static BOOL g_lock_init = FALSE;

static volatile LONG g_state = CONN_IDLE;
static volatile LONG g_want = 0;      /* 1=用户要连接 0=要断开/未连接 */
static volatile LONG g_quit = 0;
static volatile LONG g_last_pkt = 0;  /* GetTickCount() of last notify */

/* 会话序号。每次用户点「连接」+1, 正在跑的 link_session 记下自己那一轮的序号。
 *
 * 解决的问题: 旧会话收尾很慢(Close 实测能卡 19 秒)。用户在收尾期间点「取消」
 * 又点「连接」时, 旧会话结束时会把新请求的 g_want 清成 0、把状态改回"未连接",
 * 于是新请求被凭空吞掉 —— 界面一直停在"正在查找…", 其实什么都没在跑。
 * 有了序号, 旧会话发现自己已经不是最新一轮, 就不许再动 g_want / 状态。 */
static volatile LONG g_seq = 0;       /* 最近一次"连接请求"的序号 */
static volatile LONG g_cur_seq = 0;   /* 当前正在跑的那轮会话的序号 */

/* 前向声明: await_async 里要判断"用户是否还想连" */
static int want_connect(void);
/* 当前会话是否已被新请求取代(或被取消) */
static int session_stale(void)
{
    return InterlockedCompareExchange(&g_seq, 0, 0) !=
           InterlockedCompareExchange(&g_cur_seq, 0, 0);
}

/* 收尾计时起点。断开/失败后每个关闭调用都打一条耗时 ——
 * 之前出现过"点断开后 50 秒才 Close 掉设备"的情况,
 * 只看最终结果根本定位不到卡在哪一步。 */
static ULONGLONG g_td = 0;
#define TDONE(step) air_log("GATT 收尾: " step " (+%llu ms)", \
                            (unsigned long long)(GetTickCount64() - g_td))

/* 轮询等待 IAsyncOperation 完成。
 *
 * vtable 布局要注意: IAsyncOperation<T> 的 ABI vtable 只有自己的三个方法
 *   SetCompleted=6, Completed=7, GetResults=8
 * 而 Id/Status/ErrorCode/Cancel/Close 属于 IAsyncInfo, 必须 QI 过去:
 *   Id=6, Status=7, ErrorCode=8, Cancel=9, Close=10
 * 之前把槽 7 当 get_Status 用, 实际是 put_Completed(把 &st 当事件处理器),
 * 槽 13 更是越界 —— 一连设备就崩。
 *
 * 退出时(g_quit)立刻放弃等待, 否则 gatt_stop 要等满超时,
 * 而 store_close 已经删掉临界区, 线程再 ble_feed 就危险了。 */
static const IID IID_IAsyncInfo_ =
    {0x00000036,0x0000,0x0000,{0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}};

static int await_async(void* async, void** results, DWORD timeout_ms, int cancellable)
{
    ULONGLONG t0 = GetTickCount64();
    void* info = NULL;
    int rc = -1;

    if (results) *results = NULL;
    if (!async) return -1;
    {
        HRESULT hr = ((IUnknown*)async)->lpVtbl->QueryInterface(
            (IUnknown*)async, &IID_IAsyncInfo_, &info);
        if (FAILED(hr) || !info) {
            air_log("await: QI IAsyncInfo 失败 hr=0x%08lX", (unsigned long)hr);
            return -1;
        }
    }

    for (;;) {
        INT32 st = -1;
        {
            HRESULT hs = VFN(info, 7, PFN_async_status)(info, &st);
            if (FAILED(hs)) {
                /* 这条以前是静默 break: 一旦状态读不出来, 日志里就只剩
                 * "超时/失败", 和真超时完全分不开。 */
                air_log("await: get_Status 失败 hr=0x%08lX", (unsigned long)hs);
                break;
            }
        }
        /* 0=Started 1=Completed 2=Canceled 3=Error */
        if (st == 1) {
            if (!results) { rc = 0; break; }
            {
                HRESULT hr = VFN(async, 8, PFN_async_results)(async, results);
                if (FAILED(hr)) {
                    /* 最容易被忽略的一条: 操作"完成了", 但取结果时才报错。
                     * CCCD 写入 330ms 就失败、日志却一片空白, 走的就是这里。 */
                    INT32 ec = 0;
                    VFN(info, 8, PFN_async_errcode)(info, &ec);
                    air_log("await: 已完成但 GetResults 失败 hr=0x%08lX ErrorCode=0x%08lX",
                            (unsigned long)hr, (unsigned long)ec);
                    break;
                }
                /* 注意: 结果类型是"值类型"(如枚举)时, GetResults 直接把值写进
                 * 这 8 字节的前 4 字节, 看起来就像"指针为 NULL"。
                 * 所以这里不能把 NULL 当成失败 —— 由调用方按自己的结果类型判断。 */
                rc = 0;
            }
            break;
        }
        if (st == 3 || st == 2) {
            /* 操作结束但是失败的: 一定要把 HRESULT 打出来。
             * 以前这里只是 break, 返回 -1 和"超时"长得一模一样,
             * 于是日志里只剩"CCCD 写入超时", 根本看不出真实原因。 */
            INT32 ec = 0;
            VFN(info, 8, PFN_async_errcode)(info, &ec);   /* IAsyncInfo.get_ErrorCode 槽 8 */
            air_log("await: 操作失败 status=%d (2=Canceled 3=Error) hr=0x%08lX",
                    (int)st, (unsigned long)ec);
            break;
        }
        if (InterlockedCompareExchange(&g_quit, 0, 0)) {
            /* 退出中: 直接放弃, 连 Cancel 都不调 —— Cancel 本身也可能卡 */
            break;
        }
        /* 用户点了「取消/断开」, 或者又发起了一轮新的连接(序号变了), 都必须
         * 立刻打断等待。否则后台线程会握着链路把 12 秒 ×3 的枚举跑完,
         * 这段时间设备一直被占着、不广播。
         * cancellable=0 用于收尾阶段(关 CCCD), 那时必须让它走完。 */
        if (cancellable && (!want_connect() || session_stale())) {
            if (session_stale()) air_log("await: 会话已被新的连接请求取代, Cancel");
            else                 air_log("await: 用户已断开, Cancel 当前操作");
            VFN(info, 9, PFN_async_cancel)(info);   /* Cancel */
            break;
        }
        if (GetTickCount64() - t0 > timeout_ms) {
            air_log("await: 超时 %lu ms, Cancel", (unsigned long)timeout_ms);
            VFN(info, 9, PFN_async_cancel)(info);   /* Cancel */
            break;
        }
        Sleep(40);
    }

    ((IUnknown*)info)->lpVtbl->Release((IUnknown*)info);
    return rc;
}

/* 等待 IAsyncOperation<值类型> 并取出枚举值。
 *
 * 关键区别(这个坑吃了很久):
 *   IAsyncOperation<类>   -> GetResults 返回对象指针, 要用 IReference 去取 Value
 *   IAsyncOperation<枚举> -> GetResults 直接把枚举值写进出参前 4 字节
 *
 * WriteClientCharacteristicConfigurationDescriptorAsync 属于后者。
 * 以前按前者处理, 成功时读到的是 0(Success), 被当成 NULL 指针,
 * 于是"写入成功"一律被判成"失败" —— 订阅永远建立不起来。 */
static int await_async_i32(void* async, INT32* out_value, DWORD timeout_ms, int cancellable)
{
    void* holder = NULL;
    if (await_async(async, &holder, timeout_ms, cancellable) != 0) return -1;
    if (out_value) *out_value = (INT32)(INT_PTR)holder;
    return 0;
}

/* 关闭 IAsyncOperation: Close 在 IAsyncInfo 上, 必须先 QI 过去。
 * (直接在 IAsyncOperation 的 vtable 上取槽 10 是越界的) */
static void async_close(void* async){
    void* info = NULL;
    if (!async) return;
    if (SUCCEEDED(((IUnknown*)async)->lpVtbl->QueryInterface(
            (IUnknown*)async, &IID_IAsyncInfo_, &info)) && info) {
        VFN(info, 10, PFN_async_cancel)(info);      /* IAsyncInfo.Close */
        ((IUnknown*)info)->lpVtbl->Release((IUnknown*)info);
    }
}

static WCHAR g_text[160] = L"未连接 · 点「连接」开始";

static void set_state(int st, const WCHAR* text)
{
    if (g_lock_init) EnterCriticalSection(&g_lock);
    if (text) lstrcpynW(g_text, text, ARRAYSIZE(g_text));
    InterlockedExchange(&g_state, st);
    if (g_lock_init) LeaveCriticalSection(&g_lock);
    if (g_ui) PostMessageW(g_ui, WM_APP_GATT, (WPARAM)st, 0);
}

void gatt_status(WCHAR* text, int cap, int* state)
{
    if (g_lock_init) EnterCriticalSection(&g_lock);
    if (text && cap > 0) lstrcpynW(text, g_text, cap);
    if (state) *state = (int)InterlockedCompareExchange(&g_state, 0, 0);
    if (g_lock_init) LeaveCriticalSection(&g_lock);
}

BOOL gatt_busy(void)
{
    LONG s = InterlockedCompareExchange(&g_state, 0, 0);
    return (s == CONN_SCAN || s == CONN_LINK) ? TRUE : FALSE;
}

/* 主连接是否真的建立着。对时线程只在这个为真时才允许碰设备,
 * 否则"打开软件看到广播"就会去连设备, 把链路一直占着,
 * 导致设备停止广播、手机搜索不到。 */
BOOL gatt_is_connected(void)
{
    return (InterlockedCompareExchange(&g_state, 0, 0) == CONN_OK) ? TRUE : FALSE;
}

static int want_connect(void) { return InterlockedCompareExchange(&g_want, 0, 0) != 0; }

/* ---------------- 配置: 记住上次设备地址 ---------------- */
static UINT64 cfg_addr_load(void)
{
    WCHAR buf[40] = {0};
    GetPrivateProfileStringW(L"device", L"addr", L"", buf, ARRAYSIZE(buf), air_cfg_path());
    if (!buf[0]) return 0;
    return (UINT64)_wcstoui64(buf, NULL, 16);
}

static void cfg_addr_save(UINT64 a)
{
    WCHAR buf[40];
    if (!a) return;
    swprintf(buf, ARRAYSIZE(buf), L"%016llX", (unsigned long long)a);
    WritePrivateProfileStringW(L"device", L"addr", buf, air_cfg_path());
}

/* ---------------- 通知回调 ----------------
 * TypedEventHandler<GattCharacteristic, GattValueChangedEventArgs>
 *
 * WinRT 注册事件时会拿"委托接口的 IID"来 QI, 之后还会 QI IMarshal /
 * IAgileObject 等系统接口。规则:
 *   - 委托 IID 必须接受(否则 add_ValueChanged 直接失败)
 *   - IMarshal / IAgileObject 必须拒绝(接受了系统会去调我们没实现的方法)
 *
 * 坑在于: 每个事件类型的委托 IID 是完全不同的 128 位 GUID, 不是共享前缀
 * (广播监听器那个是 90EB4ECA-..., GattCharacteristic 的又是另一个值),
 * 所以不能写死。这里改成"学习": 注册过程中第一个出现的未知 IID 就是委托接口,
 * 记住它并接受, 后续同 IID 也接受, 其余一律拒绝。 */
static IID g_dlg_iid;
static volatile LONG g_dlg_ready = 0;
static volatile LONG g_qi_seen = 0;

static const IID IID_IMarshal_v =
    {0x00000003,0x0000,0x0000,{0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}};
static const IID IID_IAgileObject_v =
    {0x94ea2b94,0xe9cc,0x49e0,{0xc0,0xff,0xee,0x64,0xca,0x8f,0x5b,0x90}};

static HRESULT STDMETHODCALLTYPE val_qi(IUnknown* self, const IID* riid, void** out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    if (!riid) return E_NOINTERFACE;

    if (IsEqualIID(riid, &IID_IUnknown_v)) { *out = self; return S_OK; }

    /* 前 8 次 QI 都记日志, 万一学习错了能看出真实顺序 */
    if (InterlockedIncrement(&g_qi_seen) <= 8) {
        air_log("GATT: QI #%ld {%08lX-%04X-%04X-%02X%02X}",
                (long)InterlockedCompareExchange(&g_qi_seen, 0, 0),
                (unsigned long)riid->Data1, riid->Data2, riid->Data3,
                riid->Data4[0], riid->Data4[1]);
    }

    /* 这两个绝不能接受 */
    if (IsEqualIID(riid, &IID_IMarshal_v) || IsEqualIID(riid, &IID_IAgileObject_v))
        return E_NOINTERFACE;

    /* 第一次遇到的未知 IID 就是委托接口本身 */
    if (InterlockedCompareExchange(&g_dlg_ready, 1, 0) == 0) {
        g_dlg_iid = *riid;
        air_log("GATT: 学习到委托 IID {%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                (unsigned long)riid->Data1, riid->Data2, riid->Data3,
                riid->Data4[0], riid->Data4[1], riid->Data4[2], riid->Data4[3],
                riid->Data4[4], riid->Data4[5], riid->Data4[6], riid->Data4[7]);
    }

    if (IsEqualIID(riid, &g_dlg_iid)) { *out = self; return S_OK; }
    return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE val_addref(IUnknown* self) { (void)self; return 1; }
static ULONG STDMETHODCALLTYPE val_release(IUnknown* self) { (void)self; return 1; }
/* 不需要 GetIids: 第 4 槽被 Invoke 占用(回调实际调用位置) */
static HRESULT STDMETHODCALLTYPE val_getrtcn(IUnknown* s, HSTRING* v)
{ (void)s; return WindowsCreateString(L"", 0, v); }
static HRESULT STDMETHODCALLTYPE val_gettrust(IUnknown* s, INT32* t)
{ (void)s; if (t) *t = 0; return S_OK; }

static HRESULT STDMETHODCALLTYPE val_invoke(IUnknown* self, void* sender, void* args)
{
    (void)self; (void)sender;
    if (!args) return S_OK;

    {
        void* buf = NULL;
        /* IGattValueChangedEventArgs.get_CharacteristicValue 槽 6 */
        if (FAILED(VFN(args, 6, PFN_get_obj)(args, &buf)) || !buf) return S_OK;

        {
            BYTE raw[16];
            UINT32 n = buf_bytes(buf, raw, sizeof raw);
            if (n >= 16) {
                air_data_t d;
                static volatile LONG logged_once = 0;
                memset(&d, 0, sizeof d);
                memcpy(&d, raw, 16);      /* 8 x 小端 u16, x86 直接映射 */

                /* 第一帧把原始字节和解析结果都打出来, 便于和固件串口日志对照。
                 * 固件发送示例: tx[05 00 28 00 a7 01 b5 09 e1 1a 0e 00 00 00 e9 00]
                 *   = HCHO 5µg/m³, TVOC 40µg/m³, eCO2 423ppm, 24.85℃, 68.81%RH,
                 *     AQI 14, eCO 0.0ppm, THI 23.3 */
                if (InterlockedCompareExchange(&logged_once, 1, 0) == 0) {
                    air_log("GATT: 首帧 %02X %02X %02X %02X %02X %02X %02X %02X "
                            "%02X %02X %02X %02X %02X %02X %02X %02X",
                            raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
                            raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]);
                    air_log("GATT: 解析 HCHO=%u TVOC=%u eCO2=%u 温度=%.2f 湿度=%.2f "
                            "AQI=%u eCO=%.1f THI=%.1f",
                            (unsigned)d.hcho, (unsigned)d.tvoc, (unsigned)d.eco2,
                            d.temp_c / 100.0, d.humi / 100.0, (unsigned)d.aqi,
                            d.eco / 10.0, d.thi / 10.0);
                }

                GetSystemTimePreciseAsFileTime(&d.ft);
                ble_feed(&d);
                InterlockedExchange(&g_last_pkt, (LONG)GetTickCount());
                if (g_ui) PostMessageW(g_ui, WM_APP_DATA, 0, 0);
            }
        }
        rel((IUnknown*)buf);
    }
    return S_OK;
}

/* 委托 vtable: 第 4 槽和第 7 槽都要放 Invoke。
 * 注册时按 IInspectable(7 槽)校验, 回调时按委托 ABI(4 槽)调用第 4 槽,
 * 那里原本是 GetIids, 签名不匹配会直接崩。详见 ble.c 里同样的说明。 */
static struct { void* v[7]; } g_val_vt = {{
    (void*)val_qi, (void*)val_addref, (void*)val_release,
    (void*)val_invoke,                 /* 第 4 槽: 委托实际调用位置 */
    (void*)val_getrtcn, (void*)val_gettrust,
    (void*)val_invoke                  /* 第 7 槽 */
}};
static IUnknown g_val_handler = { (IUnknownVtbl*)&g_val_vt };

/* 重新写一次 CCCD=Notify。
 * 用途: 周期对时写完会打断设备的通知状态, 写完立刻重新开一次通知把它恢复。 */
static int cccd_enable(void* chr)
{
    void* aw = NULL;
    INT32 st = -1;
    if (!chr) return -1;
    if (FAILED(VFN(chr, 19, PFN_write_cccd)(chr, CCCD_NOTIFY, &aw)) || !aw) return -1;
    if (await_async_i32(aw, &st, 8000, 1) != 0) st = -1;
    async_close(aw);
    rel((IUnknown*)aw);
    return (st == GATT_OK) ? 0 : -1;
}

/* ---------------- 连接主流程 ---------------- */
/* 返回值: 0=用户主动断开/取消  1=连上之后掉线(可重连)  2=没能连上 */
#define LS_STOP     0
#define LS_LOST     1
#define LS_FAILED   2

static int link_session(BOOL retry)
{
    HSTRING       hcls   = NULL;
    IInspectable* fac    = NULL;
    void*         async  = NULL;
    void*         res    = NULL;
    void*         dev    = NULL;    /* IBluetoothLEDevice* */
    void*         dev3   = NULL;
    void*         svc    = NULL;
    void*         svc3   = NULL;
    void*         chr    = NULL;
    void*         session = NULL;   /* 抢占到的 GattSession, 收尾必须关掉 */
    BOOL          have_tok = FALSE;
    BOOL          cccd_on  = FALSE;
    BOOL          cancelled = FALSE;   /* 是被「断开」打断的, 不是真故障 */
    INT64         tok      = 0;
    const WCHAR*  errmsg   = NULL;
    UINT64        addr     = 0;
    int           ret      = LS_FAILED;
    WCHAR         g_msg[220];

    /* ---- 1. 拿设备地址 ----
     * 关键点: 设备如果已经被 Windows 配对/自动重连, 它就停止广播了,
     * 这时再怎么等扫描也等不到。所以次序是:
     *   1) 先看当前广播里有没有(短暂等 3 秒)
     *   2) 没有就用上次保存的地址直接连 —— 设备虽然不广播, 但地址还能连上
     *   3) 都没有才报"搜不到"
     * 之前只等 8 秒广播然后报错, 于是"设备一瞬间被系统连上, 上位机却一直
     * 显示正在搜索", 永远连不上。 */
    set_state(CONN_SCAN, L"正在搜索 PB03F-AIR…");
    {
        ULONGLONG t0 = GetTickCount64();
        while (!addr && GetTickCount64() - t0 < 3000) {
            if (!want_connect() || InterlockedCompareExchange(&g_quit, 0, 0)) {
                set_state(CONN_IDLE, L"未连接");
                return LS_STOP;
            }
            addr = ble_get_addr();
            if (!addr) Sleep(150);
        }
    }
    if (!addr) {
        addr = cfg_addr_load();
        /* 只排除全 0(真正的空值)。
         * 注意: FF:FF:FF:FF:FF:FF 是合法的 —— 很多 BLE 固件没烧 MAC 时
         * 默认就用全 F, 有些产品就是这么设定的。绝对不能当成无效地址丢弃。 */
        if (addr == 0) {
            air_log("GATT: 保存的地址是 0, 忽略");
        } else {
            /* 这里把扫描统计一起打出来。走"按旧地址直连"这条路时, 最关键的信息
             * 是"到底有没有收到过它的广播": total 很大但 named 里没有 PB03F,
             * 说明设备根本没在广播(没上电/固件卡死/被别的中心占着),
             * 那么按旧地址硬连只会白等十几秒并把链路占住。 */
            ble_stats_t st;
            ble_get_stats(&st);
            air_log("GATT: 3 秒内没收到广播, 改用上次保存的地址 %012llX 直连 "
                    "(累计广播=%u, 其中带名称=%u, 最后看到的名称=%ls)",
                    (unsigned long long)addr, st.total, st.named,
                    st.last_name[0] ? st.last_name : L"(none)");
            set_state(CONN_LINK, L"设备可能已被系统连上, 直接按已知地址连接…");
        }
    }
    if (!addr) {
        /* 带上扫描统计, 让用户知道是"监听器没起来"还是"确实没广播" */
        ble_stats_t st;
        ble_get_stats(&st);
        air_log("GATT: 扫描失败 total=%u named=%u watcher_status=%d last_name=%ls",
                st.total, st.named, st.watcher_status,
                st.last_name[0] ? st.last_name : L"(none)");

        if (!ble_radio_present()) {
            errmsg = L"本机没有蓝牙适配器 — 台式机通常需外接 USB 蓝牙";
        } else if (st.watcher_status < 0 || st.watcher_status == 4 || st.watcher_status == 5) {
            /* 监听器压根没起来, 这是根因 */
            swprintf(g_msg, ARRAYSIZE(g_msg),
                     L"蓝牙广播监听器未启动 (状态=%d) — 详见 airmon.log", st.watcher_status);
            errmsg = g_msg;
        } else if (st.total == 0) {
            errmsg = L"没收到任何广播 — 设备可能已被 Windows 自动连上。请到"
                     L"「设置→蓝牙和其他设备」里删除 PB03F-AIR 的配对, 或右键菜单「重启蓝牙服务」";
        } else if (st.named == 0) {
            swprintf(g_msg, ARRAYSIZE(g_msg),
                     L"收到 %u 个广播但都不带名称 (设备可能已被手机/浏览器占用)", st.total);
            errmsg = g_msg;
        } else {
            swprintf(g_msg, ARRAYSIZE(g_msg),
                     L"收到 %u 个广播, 名称均不匹配 (最后看到: %s)",
                     st.total, st.last_name[0] ? st.last_name : L"无名称");
            errmsg = g_msg;
        }
        goto fail;
    }

    /* ---- 2. 打开设备 ---- */
    set_state(CONN_LINK, L"正在建立连接…");
    if (FAILED(WindowsCreateString(CLASS_BLEDEV, (UINT32)lstrlenW(CLASS_BLEDEV), &hcls))) {
        errmsg = L"WinRT 初始化失败";
        goto fail;
    }
    if (FAILED(RoGetActivationFactory(hcls, &IID_IBluetoothLEDeviceStatics, (void**)&fac)) || !fac) {
        errmsg = L"蓝牙不可用 — 请确认系统蓝牙已开启 (需 Win10 1809+)";
        goto fail;
    }

    /* FromBluetoothAddressAsync 槽 7 */
    if (FAILED(VFN(fac, 7, PFN_from_addr)(fac, addr, &async)) || !async) {
        errmsg = L"打开设备失败 — 设备可能已关机或超出范围";
        goto fail;
    }
    if (await_async(async, &res, 10000, 1) != 0 || !res) {
        /* 这个超时最常见的两种原因:
           1) 设备已被别的程序/系统占用(手机 App、浏览器页面、系统自动重连)
           2) 设备关机或走远 */
        errmsg = L"连接超时 — 设备可能被其它主机占用 (关掉手机 App / 到系统设置里删除该设备配对后重试)";
        goto fail;
    }
    async_close(async);   /* Close */
    rel((IUnknown*)async); async = NULL;

    if (FAILED(qi(res, &IID_IBluetoothLEDevice, &dev)) || !dev) {
        errmsg = L"设备接口不可用";
        goto fail;
    }
    rel((IUnknown*)res); res = NULL;

    if (!want_connect()) { set_state(CONN_IDLE, L"未连接"); goto done; }

    /* 注意: 这里**不要**去"抢占 GattSession 并置 MaintainConnection=TRUE"。
     *
     * 那段代码曾导致严重副作用: 一旦置 TRUE, Windows 就认为"这个程序要求
     * 保持链路", 即使本程序退出、或服务发现失败, 这个标志也留在系统里,
     * 设备被一直占着不广播 —— 表现就是"软件退出了设备还被占用,
     * 只能关一次蓝牙才能释放"。
     * 而且它对服务发现没有任何帮助(会话本来就会随 BluetoothLEDevice 建立)。
     * 连接建立后由 IGattDeviceService3.Session 自然拿到会话即可。 */

    /* ---- 3. 找服务 5833FF05 ---- */
    set_state(CONN_LINK, L"正在查找传感器服务…");

    /* 注意: 这里**不要**提前检查 ConnectionStatus。
     * FromBluetoothAddressAsync 只是创建了设备对象, 物理链路是在第一次
     * GATT 操作(服务发现)时才真正建立的。提前查必然是 Disconnected,
     * 于是每次连接都误报"链路状态=断开"。
     * 正确的判断放在服务枚举失败之后(那时才知道链路到底通不通)。 */

    if (SUCCEEDED(qi(dev, &IID_IBluetoothLEDevice3, &dev3)) && dev3) {
        void* a2 = NULL;
        void* r2 = NULL;
        INT32 st = -1;
        BOOL  found = FALSE;
        int   attempt;

        /* 枚举服务: 先试 Cached(系统缓存, 秒回), 没有再试 Uncached(真实发现)。
         *
         * Uncached 会强制走一次完整的服务发现, 有些固件(尤其低功耗的)响应慢
         * 或丢包, 就一直卡到超时 —— 日志里"服务枚举超时"就是这样。
         * 而系统的 GATT 缓存通常在配对/上一次连接时已经建好了, 用 Cached
         * 能立刻拿到列表; 真没有才退到 Uncached。 */
        /* 3 轮: 设备正常时枚举 300ms 就回来; 慢的时候留足余地(12 秒)。
         * 之前我把它压到 2 轮/8 秒是为了缩短"失败时占住链路"的时间,
         * 但那会让本来能成的慢设备被判失败 —— 恢复成宽容值。 */
        for (attempt = 1; attempt <= 3; attempt++) {
            INT32 cache_mode;
            const char* mode_name;

            a2 = NULL; r2 = NULL; st = -1;
            /* 第 1 轮用缓存, 第 2/3 轮用真实发现 */
            cache_mode = (attempt == 1) ? CACHE_CACHED : CACHE_UNCACHED;
            mode_name  = (attempt == 1) ? "Cached" : "Uncached";

            if (FAILED(VFN(dev3, 9, PFN_svc_cache)(dev3, cache_mode, &a2)) || !a2) {
                air_log("GATT: 发起服务枚举失败 (%s, 第 %d 次)", mode_name, attempt);
            } else {
                int arc = await_async(a2, &r2, (attempt == 1) ? 3000 : 12000, 1);
                async_close(a2);
                rel((IUnknown*)a2);
                a2 = NULL;
                if (arc != 0 || !r2) {
                    air_log("GATT: 服务枚举超时 (%s, 第 %d 次)", mode_name, attempt);
                } else {
                    VFN(r2, 6, PFN_get_i32)(r2, &st);   /* Status 槽 6 */
                    if (st == GATT_OK) {
                        void* all = NULL;
                        VFN(r2, 8, PFN_get_obj)(r2, &all);   /* Services 槽 8 */
                        rel((IUnknown*)r2);
                        r2 = NULL;
                        if (all) {
                            /* 逐个看 UUID, 找 5833FF05 */
                            UINT32 n = 0, i;
                            VFN(all, 7, PFN_get_uint32)(all, &n);
                            air_log("GATT: 设备提供 %u 个服务", n);
                            for (i = 0; i < n; i++) {
                                void* s = NULL;
                                VFN(all, 6, PFN_vec_getat)(all, i, &s);
                                if (!s) continue;
                                {
                                    GUID u;
                                    memset(&u, 0, sizeof u);
                                    /* IGattDeviceService.get_Uuid 槽 9 */
                                    VFN(s, 9, PFN_get_guid)(s, &u);
                                    air_log("GATT:   服务[%u] {%08lX-%04X-%04X-%02X%02X}",
                                            i, (unsigned long)u.Data1, u.Data2, u.Data3,
                                            u.Data4[0], u.Data4[1]);
                                    if (u.Data1 == SVC_AIR.Data1 &&
                                        u.Data2 == SVC_AIR.Data2 &&
                                        u.Data3 == SVC_AIR.Data3) {
                                        if (!found) {
                                            if (FAILED(qi(s, &IID_IGattDeviceService, &svc)) || !svc) {
                                                rel((IUnknown*)s);
                                                continue;
                                            }
                                            found = TRUE;
                                        }
                                    }
                                }
                                rel((IUnknown*)s);
                            }
                            rel((IUnknown*)all);
                        }
                        if (found) break;
                        air_log("GATT: 服务列表里没有 5833FF05 (第 %d 次)", attempt);
                    } else {
                        rel((IUnknown*)r2);
                        r2 = NULL;
                        air_log("GATT: 服务枚举返回状态 %d (第 %d 次)", (int)st, attempt);
                    }
                }
            }

            if (attempt < 3) {
                if (!want_connect()) { errmsg = L"已取消"; goto fail; }
                air_log("GATT: 0.5 秒后重试服务枚举");
                for (int w = 0; w < 5; w++) {
                    if (!want_connect()) { errmsg = L"已取消"; goto fail; }
                    Sleep(100);
                }
            }
        }

        if (!found) {
            /* 不要再去读 get_ConnectionStatus: 链路异常时它会阻塞几十秒
             * (实测 59~88 秒), 而它只是为了拼一句提示。
             *
             * 这里改成带上"本轮扫描到底收到了什么", 因为最常见的真实原因
             * 不是枚举失败, 而是**设备根本没在广播** —— 那时按旧地址硬连,
             * 链路层会靠系统缓存"连上", 然后所有 GATT 请求都超时,
             * 提示语却写成"服务枚举超时", 会把人往错误方向带。 */
            ble_stats_t st2;
            ble_get_stats(&st2);
            air_log("GATT: 服务枚举失败 (最后一次状态 st=%d), 扫描统计: 累计广播=%u "
                    "带名称=%u 最后名称=%ls",
                    (int)st, st2.total, st2.named,
                    st2.last_name[0] ? st2.last_name : L"(none)");

            if (st2.named > 0 && st2.have_addr == 0) {
                /* 收得到一堆广播, 但里面没有 PB03F-AIR —— 设备没在广播 */
                swprintf(g_msg, ARRAYSIZE(g_msg),
                         L"没收到 PB03F-AIR 的广播 (已收到 %u 个其它广播) — "
                         L"设备可能未上电、未启动广播, 或已被别的中心连走",
                         st2.total);
                errmsg = g_msg;
            } else if (st == 1) {
                errmsg = L"设备不可达 (链路已断或设备不响应) — 关掉手机/其它程序后重试, "
                         L"或右键菜单「重启蓝牙服务」";
            } else if (st == 2) {
                errmsg = L"设备返回协议错误 — 详见 airmon.log";
            } else if (st == 3) {
                errmsg = L"访问被拒绝 — 设备可能要求配对后再连";
            } else {
                errmsg = L"设备连上了但读不到服务 — 详见 airmon.log";
            }
            goto fail;
        }
        /* svc 已经在上面按 UUID 挑出来了, 这里不用再解 vector */
        if (!svc) {
            errmsg = L"设备没有 5833FF05 服务 — 固件不匹配?";
            goto fail;
        }
    } else {
        /* 老系统没有 IBluetoothLEDevice3: 退回同步 GetGattService 槽 11 */
        if (FAILED(VFN(dev, 11, PFN_svc_sync)(dev, SVC_AIR, &svc)) || !svc) {
            errmsg = L"找不到 5833FF05 服务 — 固件不匹配或系统未缓存该服务";
            goto fail;
        }
    }

    /* ---- 4. 找特征 5833FF07 ----
     * 同样用"枚举全部再自己挑": IGattDeviceService3.GetCharacteristicsWithCacheModeAsync
     * 是槽 12 (13=ForUuid, 14=ForUuidWithCacheMode)。
     * 走 ForUuid 在部分固件上会卡; 枚举全部还能把真实特征 UUID 打进日志。 */
    set_state(CONN_LINK, L"正在查找传感特征…");
    if (SUCCEEDED(qi(svc, &IID_IGattDeviceService3, &svc3)) && svc3) {
        void* a3 = NULL;
        void* r3 = NULL;
        INT32 st = -1;
        void* vec = NULL;
        BOOL  chr_found = FALSE;

        /* GetCharacteristicsWithCacheModeAsync 槽 12
         * 同样先 Cached(秒回), 没有再 Uncached。 */
        {
            int ca;
            for (ca = 1; ca <= 2; ca++) {
                a3 = NULL; r3 = NULL;
                if (FAILED(VFN(svc3, 12, PFN_chr_cache)(svc3,
                        (ca == 1) ? CACHE_CACHED : CACHE_UNCACHED, &a3)) || !a3) {
                    air_log("GATT: 发起特征枚举失败 (%s)", ca == 1 ? "Cached" : "Uncached");
                    continue;
                }
                if (await_async(a3, &r3, (ca == 1) ? 3000 : 10000, 1) != 0 || !r3) {
                    async_close(a3);
                    rel((IUnknown*)a3);
                    air_log("GATT: 特征枚举超时 (%s)", ca == 1 ? "Cached" : "Uncached");
                    r3 = NULL;
                    continue;
                }
                async_close(a3);
                rel((IUnknown*)a3);
                a3 = NULL;
                break;
            }
            if (!r3) {
                errmsg = L"读取特征列表超时 — 详见 airmon.log";
                goto fail;
            }
        }

        VFN(r3, 6, PFN_get_i32)(r3, &st);
        if (st != GATT_OK) {
            rel((IUnknown*)r3);
            errmsg = L"设备拒绝访问传感特征";
            goto fail;
        }
        VFN(r3, 8, PFN_get_obj)(r3, &vec);
        rel((IUnknown*)r3);
        if (!vec) { errmsg = L"设备没有返回特征"; goto fail; }
        {
            UINT32 n = 0, i;
            VFN(vec, 7, PFN_get_uint32)(vec, &n);
            air_log("GATT: 该服务有 %u 个特征", n);
            for (i = 0; i < n; i++) {
                void* c = NULL;
                VFN(vec, 6, PFN_vec_getat)(vec, i, &c);
                if (!c) continue;
                {
                    GUID u;
                    memset(&u, 0, sizeof u);
                    VFN(c, 11, PFN_get_guid)(c, &u);   /* IGattCharacteristic.Uuid 槽 11 */
                    air_log("GATT:   特征[%u] {%08lX-%04X-%04X-%02X%02X}",
                            i, (unsigned long)u.Data1, u.Data2, u.Data3,
                            u.Data4[0], u.Data4[1]);
                    if (!chr_found &&
                        u.Data1 == CHR_SENSOR.Data1 &&
                        u.Data2 == CHR_SENSOR.Data2 &&
                        u.Data3 == CHR_SENSOR.Data3) {
                        if (SUCCEEDED(qi(c, &IID_IGattCharacteristic, &chr)) && chr)
                            chr_found = TRUE;
                    }
                }
                rel((IUnknown*)c);
            }
            rel((IUnknown*)vec);
        }
        if (!chr_found || !chr) {
            errmsg = L"没找到传感特征 5833FF07 — 详见 airmon.log 里的特征列表";
            goto fail;
        }
    } else {
        /* 退回同步 GetCharacteristics 槽 6 */
        void* vec = NULL;
        if (FAILED(VFN(svc, 6, PFN_chr_sync)(svc, CHR_SENSOR, &vec)) || !vec) {
            errmsg = L"找不到 5833FF07 特征";
            goto fail;
        }
        {
            UINT32 n = 0;
            VFN(vec, 7, PFN_get_uint32)(vec, &n);
            if (n > 0) {
                void* c0 = NULL;
                VFN(vec, 6, PFN_vec_getat)(vec, 0, &c0);
                if (c0) {
                    qi(c0, &IID_IGattCharacteristic, &chr);
                    rel((IUnknown*)c0);
                }
            }
        }
        rel((IUnknown*)vec);
        if (!chr) { errmsg = L"找不到 5833FF07 特征"; goto fail; }
    }

    /* 打一次特征属性。如果 5833FF07 根本没声明 Notify(0x10)/Indicate(0x20),
     * CCCD 写入必然失败, 而且失败得很快 —— 那就不是上位机的问题, 是固件没在
     * 这个特征上开放通知。先把事实记下来, 免得反复猜。 */
    {
        INT32 props = -1;
        VFN(chr, 7, PFN_get_i32)(chr, &props);   /* get_CharacteristicProperties 槽 7 */
        air_log("GATT: 传感特征属性=0x%X (0x02=Read 0x04=WriteNR 0x08=Write "
                "0x10=Notify 0x20=Indicate)", (unsigned)props);
    }

    /* ---- 4.5 对时: 必须在订阅之前写 ----
     *
     * 固件收到这个写请求会重置自己的通知状态。如果先订阅再写对时, 通知流就被
     * 打断了 —— 表现是"收到第一帧 -> 之后再也没有数据 -> 5 次判定掉线 ->
     * 重连 -> 设备复位", 一直循环。上一版把对时整体关掉就是踩了这个坑。
     *
     * 用户给的正确顺序: **先对时, 再订阅**。
     * 对时写 5833ff06 8 字节: 年-2000/月/日/时/分/秒/星期(0=周日)/0xAA。
     * 复用当前这条连接, 绝不自己再连一次(否则两个 GATT 客户端会互相踢线)。 */
    ULONGLONG sync_due = 0;     /* 下一次该对时的时刻(0=已经做过了) */
    if (svc) {
        if (timesync_write_on_service(svc) == 0) {
            sync_due = GetTickCount64() + 5ULL * 3600 * 1000;   /* 成功: 5 小时 */
            air_log("对时: 连接后首次对时成功(订阅之前), 下次 5 小时后");
            if (g_ui) PostMessageW(g_ui, WM_APP_BLE, 3, 0);
        } else {
            sync_due = GetTickCount64() + 5ULL * 60 * 1000;     /* 失败: 5 分钟 */
            air_log("对时: 连接后首次对时失败, 先继续订阅; 5 分钟后再试");
        }
    }

    /* ---- 5. 先挂监听, 再开通知 (顺序反了会丢首包) ----
     * 设备/协议栈在重复连接后偶发拒绝订阅, 重试几次通常就过。
     * 注意: 每次重试都要重新挂监听, 因为失败的 CCCD 写入会连带把订阅清掉。 */
    set_state(CONN_LINK, L"正在订阅数据…");
    {
        int attempt;
        BOOL ok = FALSE;

        for (attempt = 1; attempt <= 3 && !ok; attempt++) {
            INT32 st = -1;
            void* aw = NULL;

            if (attempt > 1) {
                air_log("GATT: 订阅重试 %d/3", attempt);
                for (int w = 0; w < 10; w++) {
                    if (!want_connect() || InterlockedCompareExchange(&g_quit, 0, 0)) break;
                    Sleep(100);
                }
                if (!want_connect()) { errmsg = L"已取消"; goto fail; }
            }

            /* 挂监听(重试时先摘掉上一次的) */
            if (have_tok) {
                VFN(chr, 21, PFN_rm_handler)(chr, tok);
                have_tok = FALSE;
                tok = 0;
            }
            if (FAILED(VFN(chr, 20, PFN_add_handler)(chr, &g_val_handler, &tok))) {
                air_log("GATT: add_ValueChanged 失败 (第 %d 次)", attempt);
                continue;
            }
            have_tok = TRUE;

            /* 写 CCCD = Notify */
            {
                HRESULT hw = VFN(chr, 19, PFN_write_cccd)(chr, CCCD_NOTIFY, &aw);
                if (FAILED(hw) || !aw) {
                    air_log("GATT: 发起 CCCD 写入失败 hr=0x%08lX aw=%p (第 %d 次)",
                            (unsigned long)hw, aw, attempt);
                    continue;
                }
            }
            /* 等结果。这里的结果是"枚举值"而不是对象指针, 必须用 await_async_i32,
             * 否则成功(0)会被读成 NULL 并被当成失败。 */
            if (await_async_i32(aw, &st, 8000, 1) == 0) {
                if (st == GATT_OK) {
                    ok = TRUE;
                    cccd_on = TRUE;
                    air_log("GATT: 订阅成功 (第 %d 次)", attempt);
                } else {
                    /* 1=Unreachable 2=ProtocolError 3=AccessDenied */
                    air_log("GATT: CCCD 被拒, 状态=%d (1=Unreachable 2=ProtocolError "
                            "3=AccessDenied) (第 %d 次)", (int)st, attempt);
                }
            } else {
                air_log("GATT: CCCD 写入未完成(超时/取消), 见上一条 await 日志 (第 %d 次)", attempt);
            }
            async_close(aw);
            rel((IUnknown*)aw);
        }

        if (!ok) {
            /* 之前这里说"设备可能被占用", 但复用了同一条链路就不该是这个原因,
               那个提示会误导。改成如实描述, 并指向日志里的具体状态码。 */
            errmsg = L"开启通知(CCCD 写入)失败 — 详见 airmon.log 里的状态码";
            goto fail;
        }
    }

    /* 主动读一次当前值, 首帧不用等 */
    {
        void* ar = NULL;
        if (SUCCEEDED(VFN(chr, 14, PFN_get_obj)(chr, &ar)) && ar) {   /* ReadValueAsync 槽 14 */
            void* rr = NULL;
            if (await_async(ar, &rr, 3000, 1) == 0 && rr) {
                INT32 st = -1;
                void* buf = NULL;
                VFN(rr, 6, PFN_get_i32)(rr, &st);          /* IGattReadResult.Status */
                if (st == GATT_OK) VFN(rr, 7, PFN_get_obj)(rr, &buf);   /* Value */
                if (buf) {
                    BYTE raw[16];
                    if (buf_bytes(buf, raw, sizeof raw) >= 16) {
                        air_data_t d;
                        memset(&d, 0, sizeof d);
                        memcpy(&d, raw, 16);
                        GetSystemTimePreciseAsFileTime(&d.ft);
                        ble_feed(&d);
                        InterlockedExchange(&g_last_pkt, (LONG)GetTickCount());
                        if (g_ui) PostMessageW(g_ui, WM_APP_DATA, 0, 0);
                    }
                    rel((IUnknown*)buf);
                }
                rel((IUnknown*)rr);
            }
            async_close(ar);
            rel((IUnknown*)ar);
        }
    }

    /* ---- 6. 连上了 ---- */
    if (!want_connect()) { set_state(CONN_IDLE, L"已取消 · 未连接"); goto done; }
    cfg_addr_save(addr);
    InterlockedExchange(&g_last_pkt, (LONG)GetTickCount());
    set_state(CONN_OK, L"已连接 · 接收中");
    ret = LS_STOP;      /* 之后若正常退出(用户断开)就是 0 */
    if (retry) air_notify(AIR_NOTIFY_RECONNECTED);   /* 重连成功也报一声 */

    /* ---- 6.5 对时节奏 ----
     * 首次对时已经在订阅之前做完了(见上面 4.5)。这里只说明后续节奏,
     * 由下面的保活循环执行: 成功 -> 5 小时后; 失败 -> 5 分钟后重试。 */

    /* ---- 7. 保活 ----
     * 判定要非常保守: 我们的目标是"连上就稳定", 而每次误判断线都会重连一次,
     * 重连会让设备复位 —— 那比"暂时没数据"糟糕得多。
     *   1) 最近 30 秒内收到过数据 -> 链路肯定是好的, 跳过检查
     *   2) 只有连续 15 次(约 15 秒)都报 Disconnected 才认为真掉线
     * 即使判定了, 也不再自动重连(见 gatt_thread), 只提示用户。 */
    {
        int disc = 0;
        while (want_connect() && !InterlockedCompareExchange(&g_quit, 0, 0)) {
            INT32 cs = -1;

            /* ---- 周期对时 ----
             * 只在到点时才写。写完必须重新写一次 CCCD, 把被对时打断的通知流恢复,
             * 否则会出现"对时成功但从此收不到数据"。 */
            if (svc && chr && GetTickCount64() >= sync_due) {
                int trc = timesync_write_on_service(svc);
                if (trc == 0) {
                    sync_due = GetTickCount64() + 5ULL * 3600 * 1000;   /* 成功: 5 小时 */
                    air_log("对时: 本轮成功, 下次 5 小时后");
                    if (g_ui) PostMessageW(g_ui, WM_APP_BLE, 3, 0);
                } else {
                    sync_due = GetTickCount64() + 5ULL * 60 * 1000;     /* 失败: 5 分钟 */
                    air_log("对时: 本轮失败, 5 分钟后重试");
                }
                if (cccd_enable(chr) == 0) air_log("GATT: 对时后已重新开启通知");
                else                       air_log("GATT: 对时后重新开启通知失败");
            }

            Sleep(1000);
            if (!want_connect()) break;

            {
                /* 最近 30 秒有数据 = 链路正常, 不用看状态 */
                LONG lastp = InterlockedCompareExchange(&g_last_pkt, 0, 0);
                if (lastp && (LONG)(GetTickCount() - lastp) < 30000) {
                    disc = 0;
                    continue;
                }
            }

            if (FAILED(VFN(dev, 9, PFN_get_i32)(dev, &cs)) || cs != CONN_STATUS_CONNECTED) {
                if (++disc == 1) air_log("GATT: 无数据且链路状态异常(cs=%d), 再确认", (int)cs);
                if (disc >= 15) {
                    air_log("GATT: 连续 %d 次无数据且断开, 判定掉线", disc);
                    errmsg = L"连接已断开 — 点「连接」重新连接";
                    ret = LS_LOST;
                    air_notify(AIR_NOTIFY_LOST);
                    goto fail;
                }
            } else {
                if (disc) air_log("GATT: 链路状态恢复正常");
                disc = 0;
            }
        }
    }
    goto done;

fail:
    if (errmsg) set_state(CONN_FAIL, errmsg);

done:
    g_td = GetTickCount64();
    cancelled = !want_connect();   /* 必须在下面清 g_want 之前判断 */
    /* ---- 收尾: 关通知、摘监听、放引用 ---- */
    if (chr && have_tok) {
        if (cccd_on) {
            void* aw = NULL;
            if (SUCCEEDED(VFN(chr, 19, PFN_write_cccd)(chr, CCCD_NONE, &aw)) && aw) {
                INT32 st_off = -1;
                /* 同样是"枚举值"结果, 必须用 await_async_i32 */
                await_async_i32(aw, &st_off, 2000, 0);   /* 收尾阶段不许被取消 */
                async_close(aw);
                rel((IUnknown*)aw);
            }
        }
        VFN(chr, 21, PFN_rm_handler)(chr, tok);   /* remove_ValueChanged 槽 21 */
    }
    TDONE("关通知/摘监听");

    /* 真正断开链路。
     * 只 release 引用 / 关 MaintainConnection 都不够: Windows 会继续保持
     * 物理连接几十秒甚至更久, 设备侧一直显示"已连接", 并且停止广播。
     * 必须对 GattDeviceService 调 IClosable::Close(), 让系统立刻释放 GATT 资源。
     *
     * 顺序: 先关 session -> 再 Close service(释放 GATT 客户端) -> 最后放 device。 */
    if (session) {
        VFN(session, 8, PFN_set_bool)(session, FALSE);   /* put_MaintainConnection */
        rel((IUnknown*)session);
        session = NULL;
        air_log("GATT: 已关闭 GattSession(抢占的)");
    }
    if (svc) {
        void* svc3b = NULL;
        /* IClosable.Close 槽 6: 主动释放 GATT 客户端, 立刻断开链路 */
        {
            void* cl = NULL;
            if (SUCCEEDED(qi(svc, &IID_IClosable, &cl)) && cl) {
                VFN(cl, 6, PFN_close)(cl);
                rel((IUnknown*)cl);
                air_log("GATT: 已 Close GattDeviceService");
            }
        }
        if (SUCCEEDED(qi(svc, &IID_IGattDeviceService3, &svc3b)) && svc3b) {
            void* sess2 = NULL;
            if (SUCCEEDED(VFN(svc3b, 7, PFN_get_obj)(svc3b, &sess2)) && sess2) {
                VFN(sess2, 8, PFN_set_bool)(sess2, FALSE);
                rel((IUnknown*)sess2);
                air_log("GATT: 已关闭 GattSession(服务的)");
            }
            rel((IUnknown*)svc3b);
        }
        TDONE("Close GattDeviceService");
    }

    if (chr)  rel((IUnknown*)chr);
    if (svc3) rel((IUnknown*)svc3);
    if (svc)  rel((IUnknown*)svc);
    if (dev3) rel((IUnknown*)dev3);
    TDONE("放引用");
    if (dev) {
        /* BluetoothLEDevice 也实现了 IClosable: 主动 Close 才会让系统
           真正释放这台设备的 GATT 会话, 否则连接会一直挂着。 */
        void* cl = NULL;
        if (SUCCEEDED(qi(dev, &IID_IClosable, &cl)) && cl) {
            VFN(cl, 6, PFN_close)(cl);
            rel((IUnknown*)cl);
            air_log("GATT: 已 Close BluetoothLEDevice");
        }
        rel((IUnknown*)dev);
        TDONE("Close BluetoothLEDevice");
    }
    if (res)  rel((IUnknown*)res);
    if (async) { async_close(async); rel((IUnknown*)async); }
    if (fac)  rel((IUnknown*)fac);
    if (hcls) WindowsDeleteString(hcls);

    /* 断开/失败后清掉广播缓存的地址: 下次点「连接」必须真的重新扫描。
     * 掉线(LS_LOST)时不清 —— 线程还要按同一台设备自动重连。 */
    if (ret != LS_LOST) ble_clear_addr();
    TDONE("完成");

    /* 掉线时保留 g_want=1 和 CONN_FAIL 状态, 交给线程决定是否重连;
       其它情况(用户断开 / 没能连上)才清请求并回到"未连接"。

       **关键**: 如果这一轮已经被新的连接请求取代(g_seq 变了), 就什么都不许动 ——
       否则会把用户刚点下的新请求清掉, 界面永远卡在"正在查找…"。
       这就是"点取消再点连接没反应, 再点一次取消反而连上了"的根因。 */
    if (ret != LS_LOST && session_stale()) {
        air_log("GATT: 本轮会话已被新请求取代(seq %ld -> %ld), 跳过状态收尾",
                (long)InterlockedCompareExchange(&g_cur_seq, 0, 0),
                (long)InterlockedCompareExchange(&g_seq, 0, 0));
        return ret;
    }

    if (ret != LS_LOST) {
        InterlockedExchange(&g_want, 0);
        if (ret == LS_STOP) {
            if (InterlockedCompareExchange(&g_state, 0, 0) == CONN_OK ||
                InterlockedCompareExchange(&g_state, 0, 0) == CONN_LINK ||
                InterlockedCompareExchange(&g_state, 0, 0) == CONN_SCAN) {
                set_state(CONN_IDLE, L"未连接");
            }
        } else if (cancelled) {
            /* 被「断开」打断的: 别把"服务枚举超时"这种假故障留在界面上 */
            set_state(CONN_IDLE, L"已取消 · 未连接");
        }
    }
    return ret;
}

static DWORD WINAPI gatt_thread(LPVOID p)
{
    (void)p;
    {
        HRESULT hr = RoInitialize(RO_INIT_MULTITHREADED);
        if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
            set_state(CONN_FAIL, L"WinRT 初始化失败 (需 Win10 1809+)");
            return 1;
        }
    }

    for (;;) {
        WaitForSingleObject(g_evt, INFINITE);
        if (InterlockedCompareExchange(&g_quit, 0, 0)) break;
        if (!want_connect()) continue;

        {
            /* 取一份"本轮"序号。收尾时如果发现 g_seq 已经变了, 说明用户在收尾
             * 期间又点了连接, 那么这轮的清理绝不能去动 g_want 和界面状态。 */
            InterlockedExchange(&g_cur_seq, InterlockedCompareExchange(&g_seq, 0, 0));
            int r = link_session(FALSE);

            /* ---- 自动重连 ----
             * 这个程序是常驻桌面当监视器用的, 断开就必须自己连回来, 所以这里是
             * **一直重连**, 不设次数上限。只在这两种情况下停:
             *   1) 用户点了「断开」或程序退出
             *   2) 设备已经 5 分钟没被扫到广播 —— 它多半是关机/拿远了,
             *      继续重连只会让它一上电就又被反复复位, 没有意义。
             * 每次重连前等 5 秒, 给设备留出复位后重新广播的时间。 */
            while (r == LS_LOST &&
                   want_connect() &&
                   !InterlockedCompareExchange(&g_quit, 0, 0)) {

                for (int s = 5; s > 0; s--) {
                    WCHAR msg[96];
                    swprintf(msg, ARRAYSIZE(msg), L"连接断开 · %d 秒后重连", s);
                    set_state(CONN_SCAN, msg);
                    for (int t = 0; t < 10; t++) {
                        if (!want_connect() || InterlockedCompareExchange(&g_quit, 0, 0)) break;
                        Sleep(100);
                    }
                    if (!want_connect() || InterlockedCompareExchange(&g_quit, 0, 0)) break;
                }
                if (!want_connect() || InterlockedCompareExchange(&g_quit, 0, 0)) break;

                /* 5 分钟没扫到设备就停手 */
                if (!ble_seen_within(5 * 60 * 1000)) {
                    air_log("GATT: 设备已 5 分钟没出现, 停止自动重连");
                    set_state(CONN_FAIL,
                              L"设备 5 分钟没出现 — 已停止自动重连，点「连接」再试");
                    InterlockedExchange(&g_want, 0);
                    air_notify(AIR_NOTIFY_RECONNECT_FAIL);
                    break;
                }

                set_state(CONN_LINK, L"正在重连…");
                r = link_session(TRUE);
            }

            if (r == LS_LOST && want_connect() &&
                !InterlockedCompareExchange(&g_quit, 0, 0)) {
                set_state(CONN_FAIL, L"重连中断 — 点「连接」再试");
            }
        }
    }

    RoUninitialize();
    return 0;
}

void gatt_start(HWND ui)
{
    if (!g_lock_init) { InitializeCriticalSection(&g_lock); g_lock_init = TRUE; }
    g_ui = ui;
    g_evt = CreateEventW(NULL, FALSE, FALSE, NULL);   /* 自动复位 */
    g_thread = CreateThread(NULL, 0, gatt_thread, NULL, 0, NULL);
}

void gatt_stop(void)
{
    InterlockedExchange(&g_quit, 1);
    InterlockedExchange(&g_want, 0);
    timesync_pause(1);
    if (g_evt) SetEvent(g_evt);

    if (g_thread) {
        /* link_session 的保活/发现循环会看到 g_quit 退出, 然后走 done: 清理。
           给它 10 秒; 正常情况下 1~2 秒就退干净。 */
        DWORD w = WaitForSingleObject(g_thread, 10000);
        if (w != WAIT_OBJECT_0) {
            air_log("GATT: 线程未在 10 秒内退出 — 可能卡在蓝牙系统调用里");
            /* 不再等: 直接 detach, 让进程退出时由系统回收。
               这里绝不能 CloseHandle 后继续用 g_thread,
               也绝不能为了"等清理"把退出卡死 —— 用户点了退出就该退出。 */
            g_thread = NULL;
        } else {
            CloseHandle(g_thread);
            g_thread = NULL;
        }
    }
    if (g_evt) { CloseHandle(g_evt); g_evt = NULL; }
    air_log("GATT: 已停止");
}

void gatt_connect_async(void)
{
    LONG s = InterlockedCompareExchange(&g_state, 0, 0);
    if (s == CONN_OK) return;                 /* 已经连上了 */
    /* 注意: CONN_SCAN / CONN_LINK 时也允许再点一次 —— 这时多半是上一轮
     * 收尾卡住了(Close 能卡十几秒)。发一个新序号, 让旧会话作废, 立刻重新来。
     * 以前这里直接 return, 于是"卡住时点连接没反应", 只能点取消。 */
    if (s == CONN_SCAN || s == CONN_LINK)
        air_log("GATT: 上一轮还在进行中, 作废并重新发起连接");

    InterlockedIncrement(&g_seq);             /* 新序号: 旧会话就此作废 */
    timesync_pause(0);              /* 用户主动连接: 恢复对时 */
    InterlockedExchange(&g_want, 1);
    set_state(CONN_SCAN, L"正在搜索 PB03F-AIR…");
    if (g_evt) SetEvent(g_evt);
}

void gatt_disconnect(void)
{
    LONG s = InterlockedCompareExchange(&g_state, 0, 0);
    if (s == CONN_IDLE || s == CONN_FAIL) return;
    InterlockedIncrement(&g_seq);   /* 取消也是一次"取代": 旧会话不许再改状态 */
    InterlockedExchange(&g_want, 0);
    if (g_evt) SetEvent(g_evt);   /* 让保活循环退出并清理 */
    /* 搜索/建链阶段立刻回到"未连接", 不必等后台线程收尾 */
    if (s == CONN_SCAN || s == CONN_LINK) set_state(CONN_IDLE, L"已取消 · 未连接");
    /* 用户主动断开: 对时线程也不许再去连设备, 否则设备侧一直显示已连接 */
    timesync_pause(1);
}
