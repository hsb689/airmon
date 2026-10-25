/*
 * ble.c - BLE 广播监听(纯 C, WinRT ABI 直调)
 *
 * 通过 RoActivateInstance 创建 BluetoothLEAdvertisementWatcher,
 * 注册自实现的 TypedEventHandler COM 对象接收广播,
 * 过滤设备名 PB03F-AIR, 解析 Manufacturer Data (公司 ID 0xFFFF) 8 项小端 u16。
 *
 * vtable 槽位布局(均按 WinRT IDL 声明顺序, IInspectable 占 0-5):
 *   IBluetoothLEAdvertisementWatcher: get_ScanningMode=11 put=12 Start=17 Stop=18 add_Received=19
 *   IBluetoothLEAdvertisementReceivedEventArgs: get_Advertisement=10
 *   IBluetoothLEAdvertisement: get_LocalName=8 get_ManufacturerData=11
 *   IVector<T>: GetAt=6 get_Size=7
 *   IBluetoothLEManufacturerData: get_CompanyId=6 get_Data=7
 *   IBuffer: get_Length=7
 */
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winstring.h>
#include <objbase.h>
#include <roapi.h>
#include <bluetoothapis.h>
#include <stdio.h>
#include <string.h>
#include "airmon.h"

#ifndef __EventRegistrationToken_defined /* MinGW 可能未带 eventtoken.h */
typedef struct EventRegistrationToken { INT64 value; } EventRegistrationToken;
#endif

/* ---- 接口 GUID ---- */
static const IID IID_IUnknown_ = {0x00000000,0x0000,0x0000,{0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}};
static const IID IID_IBluetoothLEAdvertisementWatcher =
    {0xa6ac336f,0xf3d3,0x4297,{0x8d,0x6c,0xc8,0x1e,0xa6,0x62,0x3f,0x40}};
static const IID IID_IBufferByteAccess =
    {0x905a0fef,0xbc53,0x11df,{0x8c,0x49,0x00,0x1e,0x4f,0xc6,0x86,0xda}};

static const WCHAR CLASS_WATCHER[] =
    L"Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementWatcher";
static const WCHAR DEV_PREFIX[] = L"PB03F";       /* 按前缀匹配设备名 */

HWND g_bleui = NULL;   /* UI 窗口句柄, main 消息循环所在线程 */

/* 发现的设备地址 (timesync.c 读取), ble.c 写入 */
UINT64 g_dev_addr = 0;
CRITICAL_SECTION g_dev_cs;

/* 诊断统计: 扫不到设备时用来告诉用户"到底收到了什么" */
static volatile LONG g_adv_total = 0;
static volatile LONG g_adv_named = 0;
/* 最后一次"认出本设备"的时刻(GetTickCount)。自动重连用它判断设备还在不在:
 * 5 分钟都没再扫到它, 就没必要一直重连 —— 无谓的重连会让设备反复复位。 */
static volatile LONG g_last_seen = 0;
static WCHAR g_last_name[64] = {0};
static BOOL  g_dev_cs_init = FALSE;
/* watcher 状态: 0=Created 1=Started 2=Stopping 3=Stopped 4=Aborted 5=Error, -1=未知 */
static volatile LONG g_watcher_status = -1;
static volatile LONG g_watcher_hr = 0;

void ble_get_stats(ble_stats_t* out)
{
    if (!out) return;
    out->total = (unsigned)InterlockedCompareExchange(&g_adv_total, 0, 0);
    out->named = (unsigned)InterlockedCompareExchange(&g_adv_named, 0, 0);
    out->watcher_status = (int)InterlockedCompareExchange(&g_watcher_status, 0, 0);
    out->have_addr = 0;
    if (g_dev_cs_init) {
        EnterCriticalSection(&g_dev_cs);
        lstrcpynW(out->last_name, g_last_name, ARRAYSIZE(out->last_name));
        out->have_addr = (g_dev_addr != 0) ? 1 : 0;
        LeaveCriticalSection(&g_dev_cs);
    } else {
        out->last_name[0] = 0;
    }
}

/* IUnknown_Release_: 项目内便捷释放 */
static ULONG IUnknown_Release_(IUnknown* p)
{
    return p ? p->lpVtbl->Release(p) : 0;
}

/* IBufferByteAccess (经典 COM, 取 IBuffer 裸指针) */
typedef struct IBufferByteAccessVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IUnknown*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IUnknown*);
    ULONG   (STDMETHODCALLTYPE *Release)(IUnknown*);
    HRESULT (STDMETHODCALLTYPE *Buffer)(IUnknown*, BYTE**);
} IBufferByteAccessVtbl;
typedef struct IBufferByteAccess {
    IBufferByteAccessVtbl *lpVtbl;
} IBufferByteAccess;

/* ---- 事件 handler COM 对象 ---- */
/* 事件委托的 IID: ITypedEventHandler<BluetoothLEAdvertisementWatcher,
 * BluetoothLEAdvertisementReceivedEventArgs> = {90EB4ECA-D465-5EA0-A61C-033C8C5ECEF2}
 *
 * 这里是整件事的坑: WinRT 注册事件时会拿这个 IID 来 QI, 而且随后还会
 * QI IMarshal / IAgileObject 等一堆接口。**只接受 IUnknown 和这个委托 IID,
 * 其余一律 E_NOINTERFACE** —— 如果对别的接口也返回 S_OK, WinRT 会去调用
 * 我们根本没实现的方法, add_Received 直接失败(E_ILLEGAL_DELEGATE_ASSIGNMENT),
 * 表现就是"监听器启动了但一个广播都收不到"。 */
static const IID IID_Delegate_ =
    {0x90EB4ECA,0xD465,0x5EA0,{0xA6,0x1C,0x03,0x3C,0x8C,0x5E,0xCE,0xF2}};

static HRESULT STDMETHODCALLTYPE hnd_qi(IUnknown* self, REFIID riid, void** out)
{
    (void)self;
    if (!out) return E_POINTER;
    *out = NULL;
    if (IsEqualIID(riid, &IID_IUnknown_) || IsEqualIID(riid, &IID_Delegate_)) {
        *out = self;
        return S_OK;
    }
    return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE hnd_addref(IUnknown* self) { (void)self; return 1; }
static ULONG STDMETHODCALLTYPE hnd_release(IUnknown* self) { (void)self; return 1; }
/* 注意: 这里不再需要 GetIids —— 它的位置(第 4 槽)被 Invoke 占了。
 * 注册时系统并不调用 GetIids, 而回调时第 4 槽必须是 Invoke。 */
static HRESULT STDMETHODCALLTYPE hnd_getrtcn(IUnknown* s, HSTRING* v)
{ (void)s; return WindowsCreateString(L"", 0, v); }
static HRESULT STDMETHODCALLTYPE hnd_gettrust(IUnknown* s, int* t)
{ (void)s; if(t)*t=0; return S_OK; }

/* IVector<T> 槽位: GetAt=6, Size=7 */
static ULONG vec_size(void* vec)
{
    ULONG n = 0;
    ((HRESULT (STDMETHODCALLTYPE**)(void*, ULONG*))(*(void***)vec))[7](vec, &n);
    return n;
}
static void* vec_getat(void* vec, ULONG i)
{
    void* it = NULL;
    ((HRESULT (STDMETHODCALLTYPE**)(void*, ULONG, void**))(*(void***)vec))[6](vec, i, &it);
    return it;
}

/* Invoke: 解析广播帧
 *
 * 匹配策略(以前是"名字必须完全等于 PB03F-AIR", 太脆, 扫不到设备):
 *   - 名称按前缀 PB03F 匹配(大小写不敏感), 兼容 PB03F-AIR / PB03F-AIR-xxxx
 *   - 名称只出现在扫描响应里时, 广播包本身没有名字 —— 不能因此丢包
 *   - 带公司 ID 0xFFFF 的 16 字节厂商数据是本设备的数据特征,
 *     只要看到它也认为"发现了设备", 地址照样记录
 */
static HRESULT STDMETHODCALLTYPE hnd_invoke(IUnknown* self, void* sender, void* eargs)
{
    (void)self; (void)sender;
    if (!eargs) return S_OK;

    IBufferByteAccess* bba = NULL;
    void* adv = NULL;
    void* vec = NULL;
    HSTRING name = NULL;
    BOOL  name_match = FALSE;
    BOOL  got_mfg = FALSE;
    air_data_t d;

    memset(&d, 0, sizeof d);

    /* 只在头几个广播时记日志, 避免刷屏; 崩溃时能看出停在哪一步 */
    {
        LONG n = InterlockedIncrement(&g_adv_total);
        if (n <= 3) air_log("BLE: 广播 #%ld 进入回调", (long)n);
    }

    /* args -> Advertisement (槽 10) */
    {
        HRESULT hr = ((HRESULT (STDMETHODCALLTYPE**)(void*, void**))
                      (*(void***)eargs))[10](eargs, &adv);
        if (FAILED(hr) || !adv) {
            air_log("BLE: get_Advertisement 失败 hr=0x%08lX", (unsigned long)hr);
            return S_OK;
        }
    }

    do {
        /* ---- 1. 名称(可能为空: 名字常在扫描响应里) ---- */
        if (SUCCEEDED(((HRESULT (STDMETHODCALLTYPE**)(void*, HSTRING*))
                       (*(void***)adv))[8](adv, &name)) && name) {
            UINT32 nlen = 0;
            const WCHAR* raw = WindowsGetStringRawBuffer(name, &nlen);
            if (raw && nlen) {
                InterlockedIncrement(&g_adv_named);
                EnterCriticalSection(&g_dev_cs);
                lstrcpynW(g_last_name, raw, ARRAYSIZE(g_last_name));
                LeaveCriticalSection(&g_dev_cs);
                if (nlen >= 5 && _wcsnicmp(raw, DEV_PREFIX, 5) == 0)
                    name_match = TRUE;
            }
        }

        /* ---- 2. 厂商数据: 公司 ID 0xFFFF ---- */
        if (SUCCEEDED(((HRESULT (STDMETHODCALLTYPE**)(void*, void**))
                       (*(void***)adv))[11](adv, &vec)) && vec) {
            ULONG n = vec_size(vec);
            if (n && InterlockedCompareExchange(&g_adv_total, 0, 0) == 1)
                air_log("BLE: 第一个广播的厂商数据段数=%u", (unsigned)n);
            for (ULONG i = 0; i < n; i++) {
                void* md = vec_getat(vec, i);
                UINT16 company = 0;
                void* buf = NULL;
                UINT32 len = 0;

                if (!md) continue;
                /* get_CompanyId (槽 6) */
                ((HRESULT (STDMETHODCALLTYPE**)(void*, UINT16*))
                 (*(void***)md))[6](md, &company);
                if (company != 0xFFFF) { IUnknown_Release_((IUnknown*)md); continue; }

                /* get_Data (槽 8: 6=CompanyId 7=SetCompanyId 8=Data 9=SetData) */
                if (FAILED(((HRESULT (STDMETHODCALLTYPE**)(void*, void**))
                            (*(void***)md))[8](md, &buf)) || !buf) {
                    IUnknown_Release_((IUnknown*)md); continue;
                }
                /* IBuffer get_Length (槽 7) */
                ((HRESULT (STDMETHODCALLTYPE**)(void*, UINT32*))
                 (*(void***)buf))[7](buf, &len);

                if (len >= 16 &&
                    SUCCEEDED(((IUnknown*)buf)->lpVtbl->QueryInterface(
                        (IUnknown*)buf, &IID_IBufferByteAccess, (void**)&bba))) {
                    BYTE* p = NULL;
                    if (SUCCEEDED(bba->lpVtbl->Buffer((IUnknown*)bba, &p)) && p) {
                        memcpy(&d, p, 16);   /* 8 x 小端 u16, x86 直接映射 */
                        GetSystemTimePreciseAsFileTime(&d.ft);
                        got_mfg = TRUE;
                    }
                    bba->lpVtbl->Release((IUnknown*)bba); bba = NULL;
                }
                IUnknown_Release_((IUnknown*)buf);
                IUnknown_Release_((IUnknown*)md);
                break;   /* 只取第一个 0xFFFF 段 */
            }
        }

        /* ---- 3. 名称对得上 或 带本设备厂商数据, 都算发现了设备 ----
         * 一发现就落盘保存地址: 设备被 Windows 自动连上后就停止广播了,
         * 下次(甚至本次)点连接时扫描根本等不到广播, 只能靠这个地址直连。 */
        if (name_match || got_mfg) {
            UINT64 a = 0;
            /* get_BluetoothAddress (槽 7: 6=RawSignalStrengthInDBm 7=BluetoothAddress
               8=AdvertisementType 9=Timestamp 10=Advertisement) */
            ((HRESULT (STDMETHODCALLTYPE**)(void*, UINT64*))
             (*(void***)eargs))[7](eargs, &a);
            if (a) {
                EnterCriticalSection(&g_dev_cs);
                g_dev_addr = a;
                LeaveCriticalSection(&g_dev_cs);
                InterlockedExchange(&g_last_seen, (LONG)GetTickCount());

                /* 立刻把地址写进配置: 设备一旦被系统连上就停止广播,
                   下次点连接时扫描等不到它, 只能靠这个地址直连。 */
                {
                    WCHAR key[32];
                    const WCHAR* cfg = air_cfg_path();
                    WCHAR old[40] = {0};
                    swprintf(key, ARRAYSIZE(key), L"%016llX", (unsigned long long)a);
                    GetPrivateProfileStringW(L"device", L"addr", L"", old, ARRAYSIZE(old), cfg);
                    if (lstrcmpiW(old, key) != 0) {
                        WritePrivateProfileStringW(L"device", L"addr", key, cfg);
                        air_log("BLE: 已记住设备地址 %ls", key);
                    }
                }
            }
        }

        /* ---- 4. 有 16 字节数据就上报 ---- */
        if (got_mfg) {
            ble_feed(&d);
            PostMessageW(g_bleui, WM_APP_DATA, 0, 0);
        }
    } while (0);

    if (name) WindowsDeleteString(name);
    if (vec) IUnknown_Release_((IUnknown*)vec);
    if (adv) IUnknown_Release_((IUnknown*)adv);
    if (InterlockedCompareExchange(&g_adv_total, 0, 0) <= 3) {
        char nb[128];
        int n = WideCharToMultiByte(CP_UTF8, 0, g_last_name, -1, nb, sizeof nb - 1, NULL, NULL);
        if (n <= 0) lstrcpynA(nb, "(none)", sizeof nb);
        nb[sizeof nb - 1] = 0;
        air_log("BLE: 广播 #%ld 回调完成 (名称匹配=%d 有数据=%d 名称=%s)",
                (long)InterlockedCompareExchange(&g_adv_total, 0, 0),
                (int)name_match, (int)got_mfg, nb);
    }
    return S_OK;
}

/* TypedEventHandler vtable.
 *
 * 这里有个非常隐蔽的坑: 注册事件(add_Received)时, WinRT 按 IInspectable 的
 * 7 槽布局校验(QI/AddRef/Release/GetIids/GetRuntimeClassName/GetTrustLevel/Invoke);
 * 但真正回调时, 它按委托的 ABI 布局(只认 IUnknown + Invoke, 共 4 槽)去调第 4 个槽。
 * 第 4 槽原本是 GetIids, 签名完全不匹配 —— 一进就访问违例, 而且栈里看不到我们的
 * 帧(崩在参数不匹配的瞬间)。所以 Invoke 必须在第 4 和第 7 槽都放一份。 */
static struct {
    void* v[7];
} g_hnd_vt = {{
    (void*)hnd_qi, (void*)hnd_addref, (void*)hnd_release,
    (void*)hnd_invoke,                 /* 第 4 槽: 委托实际调用的位置 */
    (void*)hnd_getrtcn, (void*)hnd_gettrust,
    (void*)hnd_invoke                  /* 第 7 槽: IInspectable 布局的位置 */
}};
static IUnknown g_handler = { (IUnknownVtbl*)&g_hnd_vt };

/* ---- watcher 线程 ---- */
static void* g_watcher = NULL;          /* IBluetoothLEAdvertisementWatcher* */
static volatile LONG g_run = 0;
static HANDLE g_thread = NULL;
static EventRegistrationToken g_tok = {0};

/* 单次建立并运行监听器; 返回时表示"该重建了"或"该退出了"。
 * 返回 0 = 正常结束(准备重建)  -1 = 启动失败 */
static int watcher_run_once(HWND ui)
{
    HRESULT hr;

    /* 没有无线电就别去 Start(会崩), 直接让外层等下一轮 */
    if (!ble_radio_present()) {
        return -1;
    }

    hr = RoInitialize(RO_INIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        air_log("BLE: RoInitialize 失败 hr=0x%08lX", (unsigned long)hr);
        InterlockedExchange(&g_watcher_hr, (LONG)hr);
        return -1;
    }
    air_log("BLE: watcher 线程启动");

    IInspectable* inst = NULL;
    HSTRING cls = NULL;
    if (FAILED(WindowsCreateString(CLASS_WATCHER, (UINT32)lstrlenW(CLASS_WATCHER), &cls))) goto fail;
    hr = RoActivateInstance(cls, &inst);
    WindowsDeleteString(cls);
    if (FAILED(hr) || !inst) {
        air_log("BLE: RoActivateInstance 失败 hr=0x%08lX", (unsigned long)hr);
        goto fail;
    }

    hr = ((IUnknown*)inst)->lpVtbl->QueryInterface(
        (IUnknown*)inst, &IID_IBluetoothLEAdvertisementWatcher, &g_watcher);
    IUnknown_Release_((IUnknown*)inst);
    if (FAILED(hr) || !g_watcher) {
        air_log("BLE: QI IBluetoothLEAdvertisementWatcher 失败 hr=0x%08lX", (unsigned long)hr);
        goto fail;
    }

    {
        void* w = g_watcher;
        /* 扫描模式 BluetoothLEScanningMode:
         *   0 = Passive  只听不应答, **收不到 SCAN_RSP**
         *   1 = Active   会向设备发 SCAN_REQ, 能收到扫描响应里的设备名/数据
         *   2 = None     ← 千万别用, Start() 会返回 ERROR_NOT_SUPPORTED
         *
         * 必须用 Active: 很多 BLE 固件把设备名和厂商数据放在 SCAN_RSP 里,
         * 主广播包是空的。用 Passive 时日志会一直显示
         * "名称匹配=0 有数据=0 名称=", 而手机(主动扫描)却能看到设备。 */
        INT32 mode = 1;                     /* Active */
        HRESULT hr2 = ((HRESULT (STDMETHODCALLTYPE**)(void*, INT32))
                       (*(void***)w))[12](w, mode);
        air_log("BLE: put_ScanningMode(Active=%d) hr=0x%08lX", (int)mode, (unsigned long)hr2);

        /* add_Received (槽 19) */
        hr2 = ((HRESULT (STDMETHODCALLTYPE**)(void*, IUnknown*, EventRegistrationToken*))
               (*(void***)w))[19](w, &g_handler, &g_tok);
        air_log("BLE: add_Received hr=0x%08lX tok=%lld", (unsigned long)hr2, (long long)g_tok.value);
        if (FAILED(hr2)) goto fail;

        /* Start (槽 17) */
        hr2 = ((HRESULT (STDMETHODCALLTYPE**)(void*))(*(void***)w))[17](w);
        if (FAILED(hr2)) {
            /* 把常见的 HRESULT 翻成人话, 省得每次都要查码 */
            const char* why = "未知原因";
            switch ((unsigned long)hr2) {
            case 0x80070032: why = "ERROR_NOT_SUPPORTED (扫描模式非法/被拒)"; break;
            case 0x80070005: why = "ERROR_ACCESS_DENIED (没有蓝牙访问权限)";  break;
            case 0x8007001F: why = "ERROR_GEN_FAILURE (蓝牙设备异常)";        break;
            case 0x80070015: why = "ERROR_NOT_READY (蓝牙未就绪)";            break;
            case 0x8007048F: why = "ERROR_DEVICE_NOT_CONNECTED (无蓝牙适配器)"; break;
            case 0x80070490: why = "ERROR_NOT_FOUND (找不到蓝牙无线电)";      break;
            }
            air_log("BLE: Start 失败 hr=0x%08lX — %s", (unsigned long)hr2, why);
            goto fail;
        }
        air_log("BLE: Start hr=0x%08lX (ok)", (unsigned long)hr2);

        /* get_Status (槽 10) 自检: Start 返回 S_OK 不代表真的跑起来了。
           没有可用蓝牙无线电时这里会一直是 0(Created), 之后系统内部会崩,
           所以状态不对就主动收手, 不要硬撑。 */
        {
            INT32 st = -1;
            int   i;
            for (i = 0; i < 10; i++) {          /* 最多等 1 秒 */
                st = -1;
                ((HRESULT (STDMETHODCALLTYPE**)(void*, INT32*))
                 (*(void***)w))[10](w, &st);
                if (st == 1 || st == 4 || st == 5) break;   /* Started / Aborted / Error */
                Sleep(100);
            }
            air_log("BLE: get_Status status=%d (0=Created 1=Started 2=Stopping 3=Stopped 4=Aborted 5=Error)",
                    (int)st);
            InterlockedExchange(&g_watcher_status, (LONG)st);

            if (st != 1) {
                air_log("BLE: 监听器没能进入 Started(通常是蓝牙无线电不可用), 主动停止");
                ((HRESULT (STDMETHODCALLTYPE**)(void*))(*(void***)w))[18](w);  /* Stop */
                goto fail;
            }
        }
    }

    PostMessageW(ui, WM_APP_BLE, 1, 0);   /* started */
    air_log("BLE: 进入等待循环 g_run=%ld", (long)InterlockedCompareExchange(&g_run, 0, 0));

    /* 等待循环里顺便做健康检查:
     *  1) 用户关掉再打开 Windows 蓝牙后, watcher 会变成 Stopped/Aborted,
     *     之后再也不会有回调 —— 界面就永远"收不到广播"。
     *  2) 更隐蔽的一种: 状态还是 Started, 但系统栈内部已经卡住, 也收不到广播。
     *     所以除了看状态, 还要看"多久没收到广播了"。 */
    {
        int tick = 0;
        ULONGLONG last_seen = GetTickCount64();
        LONG last_total = InterlockedCompareExchange(&g_adv_total, 0, 0);

        while (InterlockedCompareExchange(&g_run, 0, 0)) {
            LONG now_total;
            Sleep(200);

            now_total = InterlockedCompareExchange(&g_adv_total, 0, 0);
            if (now_total != last_total) {
                last_total = now_total;
                last_seen  = GetTickCount64();
            }

            if (++tick < 10) continue;      /* 约 2 秒检查一次 */
            tick = 0;

            {
                void* w = g_watcher;
                INT32 st = -1;
                if (!w) break;
                ((HRESULT (STDMETHODCALLTYPE**)(void*, INT32*))
                 (*(void***)w))[10](w, &st);
                InterlockedExchange(&g_watcher_status, (LONG)st);

                if (st != 1) {
                    air_log("BLE: 监听器状态变成 %d, 重启监听", (int)st);
                    break;
                }
                /* 状态正常但 30 秒一个广播都没有: 多半是栈卡住了, 重建 */
                if (GetTickCount64() - last_seen > 30000) {
                    air_log("BLE: 30 秒没收到任何广播, 重建监听器");
                    break;
                }
            }
        }
    }
    air_log("BLE: 退出等待循环, 开始 Stop");

    /* 停掉当前 watcher */
    if (g_watcher) {
        void* w = g_watcher;
        /* Stop (槽 18) */
        ((HRESULT (STDMETHODCALLTYPE**)(void*))(*(void***)w))[18](w);
        IUnknown_Release_((IUnknown*)w);
        g_watcher = NULL;
    }
    air_log("BLE: watcher 已停止, 累计收到 %u 个广播",
            (unsigned)InterlockedCompareExchange(&g_adv_total, 0, 0));

    if (g_watcher) {
        void* w = g_watcher;
        /* Stop (槽 18) */
        ((HRESULT (STDMETHODCALLTYPE**)(void*))(*(void***)w))[18](w);
        IUnknown_Release_((IUnknown*)w);
        g_watcher = NULL;
    }

    RoUninitialize();
    return 0;          /* 0 = 需要重建(调用方决定) */

fail:
    air_log("BLE: 启动失败 (见上一条)");
    PostMessageW(ui, WM_APP_BLE, 2, 0);
    if (g_watcher) { IUnknown_Release_((IUnknown*)g_watcher); g_watcher = NULL; }
    RoUninitialize();
    return 1;
}

/* 线程主体: 反复建立/重建监听器。
 * 蓝牙被关掉再打开、监听器 Aborted 时都靠这里自动恢复,
 * 不用重启软件。 */
static DWORD WINAPI watcher_thread(LPVOID param)
{
    HWND ui = (HWND)param;
    int  fails = 0;

    while (InterlockedCompareExchange(&g_run, 0, 0)) {
        int rc = watcher_run_once(ui);

        if (!InterlockedCompareExchange(&g_run, 0, 0)) break;

        if (rc != 0) {
            /* 启动失败: 退避重试(蓝牙可能还没打开) */
            fails++;
            if (fails > 120) {                 /* 约 10 分钟还没成功就放弃 */
                air_log("BLE: 连续 %d 次启动失败, 停止重试", fails);
                PostMessageW(ui, WM_APP_BLE, 2, 0);
                break;
            }
            air_log("BLE: 启动失败, 5 秒后重试 (第 %d 次)", fails);
            for (int i = 0; i < 50; i++) {
                if (!InterlockedCompareExchange(&g_run, 0, 0)) break;
                Sleep(100);
            }
        } else {
            /* 正常运行后失效(蓝牙被关掉等): 稍等再重建 */
            fails = 0;
            air_log("BLE: 2 秒后重建监听器");
            for (int i = 0; i < 20; i++) {
                if (!InterlockedCompareExchange(&g_run, 0, 0)) break;
                Sleep(100);
            }
        }
    }
    air_log("BLE: watcher 线程退出");
    return 0;
}

/* 本机是否存在蓝牙无线电(适配器)。用经典蓝牙 API 探测, 不涉及 WinRT。 */
int ble_radio_present(void)
{
    BLUETOOTH_FIND_RADIO_PARAMS p;
    HBLUETOOTH_RADIO_FIND h;
    HANDLE radio = NULL;
    int found = 0;

    p.dwSize = sizeof p;
    h = BluetoothFindFirstRadio(&p, &radio);
    if (h) {
        found = 1;
        if (radio) CloseHandle(radio);
        BluetoothFindRadioClose(h);
    }
    return found;
}

int ble_start(HWND notify_wnd)
{
    InitializeCriticalSection(&g_dev_cs);
    g_dev_cs_init = TRUE;
    g_bleui = notify_wnd;

    /* 没有蓝牙无线电时不能去 Start: 那种情况下 Start 会"假成功",
       随后系统在 Windows.Devices.Bluetooth.dll 里访问违例直接崩掉进程。
       但也不就此放弃 —— 用户可能之后才打开蓝牙, 所以线程照常启动,
       由它自己轮询等待无线电出现。 */
    if (!ble_radio_present()) {
        air_log("BLE: 当前没有蓝牙无线电, 进入等待(打开蓝牙后会自动开始)");
        PostMessageW(notify_wnd, WM_APP_BLE, 3, 0);   /* 3=没有蓝牙适配器 */
    }

    InterlockedExchange(&g_run, 1);
    g_thread = CreateThread(NULL, 0, watcher_thread, notify_wnd, 0, NULL);
    return g_thread ? 0 : -1;
}

void ble_stop(void)
{
    InterlockedExchange(&g_run, 0);
    if (g_thread) {
        WaitForSingleObject(g_thread, 3000);
        CloseHandle(g_thread);
        g_thread = NULL;
    }
}

/* gatt.c 主动连接用: 最近一次广播里对得上名字的设备地址, 0=还没发现 */
UINT64 ble_get_addr(void)
{
    UINT64 a;
    if (!g_dev_cs_init) return 0;      /* 还没 ble_start 就别碰临界区 */
    EnterCriticalSection(&g_dev_cs);
    a = g_dev_addr;
    LeaveCriticalSection(&g_dev_cs);
    return a;
}

/* 最近 ms 毫秒内是否扫到过本设备的广播。
 * 自动重连靠它决定"还要不要再试": 设备一直不出现就没必要反复重连。 */
int ble_seen_within(DWORD ms)
{
    LONG t = InterlockedCompareExchange(&g_last_seen, 0, 0);
    if (!t) return 0;
    return ((DWORD)(GetTickCount() - (DWORD)t) <= ms) ? 1 : 0;
}

/* 断开/失败后清掉缓存的设备地址。
 *
 * 不清的话, 下次点「连接」时 link_session 一进 while 就立刻拿到这个旧地址,
 * 跳过真正的扫描, 直接按旧地址去连 —— 而设备其实可能已经不在广播了,
 * 于是必然卡在服务枚举超时。界面上就成了"扫不到设备, 但程序还在连",
 * 用户完全看不出它在连什么。 */
void ble_clear_addr(void)
{
    if (!g_dev_cs_init) return;
    EnterCriticalSection(&g_dev_cs);
    g_dev_addr = 0;
    LeaveCriticalSection(&g_dev_cs);
}
