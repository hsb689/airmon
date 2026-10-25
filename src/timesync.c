/*
 * timesync.c - BLE 连接 + 对时服务写入 (纯 C, WinRT ABI)
 *
 * 设备连接由 Windows 系统级配对完成(用户在 设置-设备 里连 PB03F-AIR,
 * Windows 会自动重连)。本模块只负责:
 *   1. 记录广播里发现的设备地址 (ble.c 回调写 g_dev_addr)
 *   2. 每 5 小时 + 程序启动后首次发现设备时, 通过 GATT 写对时特征:
 *      服务 5833FF05-9B8B-5191-6142-22A4536EF123
 *      特征 5833FF06-9B8B-5191-6142-22A4536EF123
 *      8 字节: [年-2000][月][日][时][分][秒][星期(0=周日)][0xAA]
 *
 * 槽位(均含 0-5 IInspectable 前置):
 *   IBluetoothLEDeviceStatics(c8cf1a19): FromIdAsync=8 FromBluetoothAddressAsync=9
 *   IBluetoothLEDevice(b5ee2f7b): get_ConnectionStatus=9 GetGattService=11
 *   IGattDeviceService(ac7b7c05): GetCharacteristics=6 get_Uuid=9
 *   IGattCharacteristic(59cb50c1): get_Uuid=11 WriteValueAsync=16
 *   IGattCharacteristicsResult(1194945C): get_Status=6 get_Characteristics=8
 *   ICryptographicBufferStatics(320b7e22): CreateFromByteArray=9
 *   IAsyncOperation: get_Status=7 Cancel=9 Close=10 GetResults=13 (继承 IAsyncInfo)
 */
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winstring.h>
#include <objbase.h>
#include <roapi.h>
#include <stdio.h>
#include <string.h>
#include "airmon.h"

/* ---- GUID ---- */
static const IID IID_IBluetoothLEDeviceStatics =
    {0xc8cf1a19,0xf0b6,0x4bf0,{0x86,0x89,0x41,0x30,0x3d,0xe2,0xd9,0xf4}};
static const IID IID_IBluetoothLEDevice =
    {0xb5ee2f7b,0x4ad8,0x4642,{0xac,0x48,0x80,0xa0,0xb5,0x00,0xe8,0x87}};
static const IID IID_IGattCharacteristic =
    {0x59cb50c1,0x5934,0x4f68,{0xa1,0x98,0xeb,0x86,0x4f,0xa4,0x4e,0x6b}};
static const IID IID_ICryptographicBufferStatics =
    {0x320b7e22,0x3cb0,0x4cdf,{0x86,0x63,0x1d,0x28,0x91,0x00,0x65,0xeb}};

static const WCHAR CLASS_BLEDEV[]  = L"Windows.Devices.Bluetooth.BluetoothLEDevice";
static const WCHAR CLASS_CRYPTO[]  = L"Windows.Security.Cryptography.CryptographicBuffer";

/* 固件对时服务 (标准 128 位 BLE UUID, 小字节序展开) */
static const GUID SVC_TIME =
    {0x5833FF05,0x9B8B,0x5191,{0x61,0x42,0x22,0xA4,0x53,0x6E,0xF1,0x23}};
/* 对时特征 5833FF06 —— 以前这里误用了服务 UUID, 永远找不到特征 */
static const GUID CHR_TIME =
    {0x5833FF06,0x9B8B,0x5191,{0x61,0x42,0x22,0xA4,0x53,0x6E,0xF1,0x23}};

/* ble.c 写入 */
/* 设备地址通过 ble_get_addr() 取, 不要直接碰 g_dev_cs:
 * 那个临界区是 ble_start() 初始化的, 没走蓝牙时会崩。 */

/* ---- 小工具 ---- */
static ULONG rel(IUnknown* p) { return p ? p->lpVtbl->Release(p) : 0; }

/* 调用 COM 对象 vtable 第 slot 槽, 返回 HRESULT */
#define VCALL(obj, slot, ...) \
    (((HRESULT (STDMETHODCALLTYPE **)(void *, ...))(*(void ***)(obj)))[(slot)])((obj), ##__VA_ARGS__)

/* 带 GUID 参数的方法必须用类型化函数指针调用: 走上面的可变参数宏时,
 * x64 ABI 会把 16 字节结构体按引用传递, 被调方拿到的 GUID 是错的。
 * (之前 FromBluetoothAddressAsync 用槽 9、GetGattService 用 VCALL 传 GUID,
 *  两处都不对, 对时一直没成功。) */
typedef HRESULT (STDMETHODCALLTYPE *PFN_from_addr)(void*, UINT64, void**);
typedef HRESULT (STDMETHODCALLTYPE *PFN_get_svc)(void*, GUID, void**);
typedef HRESULT (STDMETHODCALLTYPE *PFN_get_chr)(void*, GUID, void**);
typedef HRESULT (STDMETHODCALLTYPE *PFN_get_obj_x)(void*, void**);
typedef HRESULT (STDMETHODCALLTYPE *PFN_set_bool_x)(void*, BOOL);
#define VFN(obj, slot, type) ((type)(*(void***)(obj))[(slot)])

/* GattSession 用到的接口 */
static const IID IID_IGattDeviceService3_x =
    {0xb293a950,0x0c53,0x437c,{0xa9,0xb3,0x5c,0x32,0x10,0xc6,0xe5,0x69}};

/* 轮询等待 IAsyncOperation 完成, 返回 0 且 *results 可用。
 *
 * 注意 vtable 布局: IAsyncOperation<T> 的 ABI vtable 只有自己的三个方法
 *   SetCompleted=6, Completed=7, GetResults=8
 * 状态/取消/关闭属于 IAsyncInfo, 必须 QI 过去:
 *   Id=6, Status=7, ErrorCode=8, Cancel=9, Close=10
 * 之前直接拿槽 7 当 get_Status 用, 实际是 put_Completed ——
 * 把 &st 当事件处理器交给系统, 一连上设备就崩。 */
static const IID IID_IAsyncInfo_ =
    {0x00000036,0x0000,0x0000,{0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}};

typedef HRESULT (STDMETHODCALLTYPE *PFN_async_status)(void*, INT32*);
typedef HRESULT (STDMETHODCALLTYPE *PFN_async_cancel)(void*);
typedef HRESULT (STDMETHODCALLTYPE *PFN_async_close)(void*);
typedef HRESULT (STDMETHODCALLTYPE *PFN_async_results)(void*, void**);

static int await_async(void* async, void** results, DWORD timeout_ms)
{
    ULONGLONG t0 = GetTickCount64();
    void* info = NULL;
    int rc = -1;

    if (results) *results = NULL;
    if (!async) return -1;
    if (FAILED(((IUnknown*)async)->lpVtbl->QueryInterface(
            (IUnknown*)async, &IID_IAsyncInfo_, &info)) || !info) return -1;

    for (;;) {
        INT32 st = -1;
        if (FAILED(VFN(info, 7, PFN_async_status)(info, &st))) break;
        /* 0=Started 1=Completed 2=Canceled 3=Error */
        if (st == 1) {
            if (!results) { rc = 0; break; }
            rc = SUCCEEDED(VFN(async, 8, PFN_async_results)(async, results)) ? 0 : -1;
            break;
        }
        if (st == 3 || st == 2) break;
        if (GetTickCount64() - t0 > timeout_ms) {
            VFN(info, 9, PFN_async_cancel)(info);   /* Cancel */
            break;
        }
        Sleep(40);
    }

    ((IUnknown*)info)->lpVtbl->Release((IUnknown*)info);
    return rc;
}

/* 关闭 IAsyncOperation: Close 属于 IAsyncInfo, 必须先 QI 过去。
 * 直接在 IAsyncOperation 的 vtable 上取槽 10 是越界的, 会崩。 */
static void async_close(void* async){
    void* info = NULL;
    if (!async) return;
    if (SUCCEEDED(((IUnknown*)async)->lpVtbl->QueryInterface(
            (IUnknown*)async, &IID_IAsyncInfo_, &info)) && info) {
        VFN(info, 10, PFN_async_cancel)(info);
        ((IUnknown*)info)->lpVtbl->Release((IUnknown*)info);
    }
}

/* IAsyncOperation<值类型> 取结果。
 *
 * WriteValueAsync 返回 IAsyncOperation<GattCommunicationStatus>, 而
 * GattCommunicationStatus 是**枚举(值类型)** —— 这种 IAsyncOperation 的
 * GetResults 直接把枚举值写进出参的前 4 字节, 不返回 IReference 对象指针。
 *
 * 以前这里按"IReference 对象"处理: 写入成功时 GetResults 写 0(Success),
 * 被当成 NULL 指针, 于是**明明写成功也被判成失败** —— 这就是"对时永远
 * 对不上"的真正原因(和 CCCD 订阅是同一个坑)。 */
static int await_async_i32(void* async, INT32* out_value, DWORD timeout_ms)
{
    void* holder = NULL;
    if (await_async(async, &holder, timeout_ms) != 0) return -1;
    if (out_value) *out_value = (INT32)(INT_PTR)holder;
    return 0;
}
/* 构造对时 8 字节:
 *   [0] 年-2000  [1] 月  [2] 日  [3] 时  [4] 分  [5] 秒
 *   [6] 星期(0=周日)  [7] 0xAA(已对时标志)
 * 固件要求长度必须正好 8 字节, 否则回 ATT_ERR_INVALID_VALUE_SIZE。 */
static void build_time_packet(BYTE out[8])
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    out[0] = (BYTE)(st.wYear >= 2000 ? st.wYear - 2000 : 0);
    out[1] = (BYTE)st.wMonth;
    out[2] = (BYTE)st.wDay;
    out[3] = (BYTE)st.wHour;
    out[4] = (BYTE)st.wMinute;
    out[5] = (BYTE)st.wSecond;
    out[6] = (BYTE)st.wDayOfWeek;
    out[7] = 0xAA;
}

/* 写一次对时; 返回 0 成功 */
/* ---------------- 在已有连接上写对时 ----------------
 *
 * 这是现在唯一推荐的用法: gatt.c 已经把链路建好了, 直接复用它的
 * GattDeviceService 写对时特征。
 *
 * 以前是对时线程自己 FromBluetoothAddressAsync 再连一次设备 ——
 * 同一台设备上出现两条 GATT 客户端, 对时那条结束时我把 service/device
 * Close() 掉了, 结果把主连接也一起关了。
 * 表现就是: 连上 -> 收到 1 帧 -> 立刻断开 -> 再连又重复。
 *
 * svc 是 IGattDeviceService*, 由调用方持有, 这里不负责释放它。 */
int timesync_write_on_service(void* svc)
{
    void* stats = NULL;
    void* chr = NULL;
    void* buf = NULL;
    void* vec = NULL;
    void* async_w = NULL;
    HSTRING h1 = NULL;
    int rc = -1;
    INT32 st = -1;

    if (!svc) return -1;

    /* 1. 组 8 字节时间包 -> IBuffer */
    if (FAILED(WindowsCreateString(CLASS_CRYPTO, (UINT32)lstrlenW(CLASS_CRYPTO), &h1))) return -1;
    if (FAILED(RoGetActivationFactory(h1, &IID_ICryptographicBufferStatics, &stats)) || !stats) {
        WindowsDeleteString(h1);
        return -1;
    }
    WindowsDeleteString(h1);
    {
        BYTE pkt[8];
        build_time_packet(pkt);
        if (FAILED(VCALL(stats, 9, (UINT32)sizeof pkt, pkt, &buf)) || !buf) {
            rel((IUnknown*)stats);
            return -1;
        }
    }
    rel((IUnknown*)stats);

    /* 2. 找对时特征 5833FF06 (同步 GetCharacteristics, 槽 6) */
    if (FAILED(VFN(svc, 6, PFN_get_chr)(svc, CHR_TIME, &vec)) || !vec) {
        air_log("对时: 找不到 5833FF06 特征");
        rel((IUnknown*)buf);
        return -1;
    }
    {
        UINT32 n = 0;
        VCALL(vec, 7, &n);                      /* get_Size */
        if (n > 0) {
            void* c0 = NULL;
            VCALL(vec, 6, 0, &c0);              /* GetAt */
            if (c0) {
                if (FAILED(((IUnknown*)c0)->lpVtbl->QueryInterface((IUnknown*)c0,
                        &IID_IGattCharacteristic, &chr))) chr = NULL;
                rel((IUnknown*)c0);
            }
        }
        rel((IUnknown*)vec);
    }
    if (!chr) {
        air_log("对时: 拿不到对时特征");
        rel((IUnknown*)buf);
        return -1;
    }

    /* 3. WriteValueAsync (槽 16) */
    if (FAILED(VCALL(chr, 16, buf, &async_w)) || !async_w) {
        air_log("对时: WriteValueAsync 发起失败");
        rel((IUnknown*)chr);
        rel((IUnknown*)buf);
        return -1;
    }
    {
        INT32 wst = -1;
        if (await_async_i32(async_w, &wst, 5000) == 0) {
            st = wst;
        } else {
            air_log("对时: WriteValueAsync 等待失败(超时/取消)");
        }
        async_close(async_w);
        rel((IUnknown*)async_w);
    }
    rc = (st == 0) ? 0 : -1;
    if (st == 0)
        air_log("对时: 写入成功 (status=0 Success)");
    else if (st < 0)
        air_log("对时: 写入失败 (等不到结果)");
    else
        air_log("对时: 写入被拒 status=%d (1=Unreachable 2=ProtocolError 3=AccessDenied)",
                (int)st);

    rel((IUnknown*)chr);
    rel((IUnknown*)buf);
    return rc;
}

int ble_timesync_once(void)
{
    UINT64 addr = ble_get_addr();
    if (!addr) return -1;

    HRESULT hrCo = RoInitialize(RO_INIT_MULTITHREADED);
    int rc = -1;
    void* stats = NULL;
    void* dev = NULL;
    void* svc = NULL;
    void* chr = NULL;
    void* buf = NULL;
    HSTRING h1 = NULL, h2 = NULL;

    if (FAILED(hrCo) && hrCo != RPC_E_CHANGED_MODE) return -1;

    do {
        /* CryptographicBuffer.CreateFromByteArray (槽 9) -> IBuffer */
        if (FAILED(WindowsCreateString(CLASS_CRYPTO, (UINT32)lstrlenW(CLASS_CRYPTO), &h1))) break;
        if (FAILED(RoGetActivationFactory(h1, &IID_ICryptographicBufferStatics, &stats)) || !stats) break;

        BYTE pkt[8];
        build_time_packet(pkt);
        if (FAILED(VCALL(stats, 9, (UINT32)sizeof pkt, pkt, &buf)) || !buf) break;
    } while (0);

    /* BluetoothLEDevice.FromBluetoothAddressAsync -> GATT 写入 */
    do {
        IInspectable* finst = NULL;
        if (FAILED(WindowsCreateString(CLASS_BLEDEV, (UINT32)lstrlenW(CLASS_BLEDEV), &h2))) break;
        if (FAILED(RoGetActivationFactory(h2, &IID_IBluetoothLEDeviceStatics, (void**)&finst)) || !finst) break;

        void* async_dev = NULL;
        /* FromBluetoothAddressAsync 是槽 7 (FromIdAsync=6, GetDeviceSelector=8) */
        if (FAILED(VFN(finst, 7, PFN_from_addr)(finst, addr, &async_dev)) || !async_dev) {
            air_log("对时: FromBluetoothAddressAsync 失败");
            rel((IUnknown*)finst); break;
        }
        void* rdev = NULL;
        {
            int rc = await_async(async_dev, &rdev, 5000);
            air_log("对时: await 打开设备 rc=%d rdev=%p", rc, rdev);
            if (rc == 0 && rdev) {
                /* QI 默认接口 */
                if (FAILED(((IUnknown*)rdev)->lpVtbl->QueryInterface((IUnknown*)rdev,
                        &IID_IBluetoothLEDevice, &dev))) dev = NULL;
                rel((IUnknown*)rdev);
            }
        }
        async_close(async_dev);   /* Close 在 IAsyncInfo 上, 不能直接取槽 10 */
        rel((IUnknown*)async_dev);
        rel((IUnknown*)finst);
        if (!dev) { air_log("对时: 拿不到 IBluetoothLEDevice"); break; }

        /* dev.GetGattService(uuid) (槽 11) — 同步, 需系统已缓存该服务 */
        if (FAILED(VFN(dev, 11, PFN_get_svc)(dev, SVC_TIME, &svc)) || !svc) {
            air_log("对时: GetGattService 失败");
            break;
        }
        air_log("对时: 找到对时服务");

        /* svc.GetCharacteristics(uuid) (槽 6) -> IVectorView */
        void* vec = NULL;
        if (FAILED(VFN(svc, 6, PFN_get_chr)(svc, CHR_TIME, &vec)) || !vec) break;
        ULONG n = 0;
        VCALL(vec, 7, &n);      /* get_Size */
        if (n > 0) {
            void* c = NULL;
            VCALL(vec, 6, 0, &c);   /* GetAt */
            if (c && SUCCEEDED(((IUnknown*)c)->lpVtbl->QueryInterface((IUnknown*)c,
                    &IID_IGattCharacteristic, &chr))) {
                rel((IUnknown*)c);
            } else if (c) rel((IUnknown*)c);
        }
        rel(vec);
        if (!chr) break;

        /* chr.WriteValueAsync(buf) (槽 16) -> IAsyncOperation<GattCommunicationStatus> */
        void* async_w = NULL;
        if (FAILED(VCALL(chr, 16, buf, &async_w)) || !async_w) break;
        INT32 st = -1;
        void* res = NULL;
        if (await_async(async_w, &res, 5000) == 0) {
            /* res 是 IReference<GattCommunicationStatus>: get_Value 槽 6 */
            VCALL(res, 6, &st);
            rel((IUnknown*)res);
        }
        async_close(async_w);      /* Close 在 IAsyncInfo 上, 不能取槽 10 */
        rel((IUnknown*)async_w);
        rc = (st == 0) ? 0 : -1;   /* GattCommunicationStatus::Success */
    } while (0);

    /* 关键: 对时用完必须真正断开链路。
     * 只 release 引用的话 Windows 会继续持有连接, 设备停止广播,
     * 手机就搜不到它了 —— 用户看到的现象就是"软件关掉后还得手动关蓝牙"。 */
    if (svc) {
        void* svc3 = NULL;
        if (SUCCEEDED(((IUnknown*)svc)->lpVtbl->QueryInterface((IUnknown*)svc,
                &IID_IGattDeviceService3_x, &svc3)) && svc3) {
            void* sess = NULL;
            /* IGattDeviceService3.Session = 槽 7 */
            if (SUCCEEDED(VFN(svc3, 7, PFN_get_obj_x)(svc3, &sess)) && sess) {
                VFN(sess, 8, PFN_set_bool_x)(sess, FALSE);   /* put_MaintainConnection */
                rel((IUnknown*)sess);
            }
            rel((IUnknown*)svc3);
        }
    }

    if (buf) rel((IUnknown*)buf);
    if (chr) rel((IUnknown*)chr);
    if (svc) rel((IUnknown*)svc);
    if (dev) rel((IUnknown*)dev);
    if (stats) rel((IUnknown*)stats);
    if (h1) WindowsDeleteString(h1);
    if (h2) WindowsDeleteString(h2);
    RoUninitialize();
    return rc;
}

/* 对时线程。
 *
 * 触发条件非常关键: 必须"主连接(gatt)已经建立"才允许去写对时。
 * 之前只要看到广播地址就去连设备 —— 于是"打开软件、附近有 PB03F-AIR"
 * 就会把它连上, Windows 蓝牙栈一直持着链路, 设备停止广播,
 * 手机就再也搜不到它, 只能关蓝牙强制断开。
 *
 * 现在: 打开软件不碰设备; 只有用户点了「连接」并真正连上之后, 才写一次对时。
 */
static volatile LONG g_ts_paused = 0;

void timesync_pause(int pause)
{
    LONG old = InterlockedExchange(&g_ts_paused, pause ? 1 : 0);
    /* 只在状态真的变化时记一条, 否则每次点连接都会刷一行"恢复", 干扰日志 */
    if ((old != 0) != (pause != 0))
        air_log("对时: %s", pause ? "暂停(不再碰设备)" : "恢复");
}

/* 现在允许写对时吗: 未暂停 + 主连接已建立 */
static BOOL ts_allowed(void)
{
    if (InterlockedCompareExchange(&g_ts_paused, 0, 0)) return FALSE;
    if (ble_get_addr() == 0) return FALSE;
    return gatt_is_connected();
}

static DWORD WINAPI timesync_thread(LPVOID p)
{
    HWND ui = (HWND)p;
    ULONGLONG last = GetTickCount64();
    BOOL done_once = FALSE;

    for (;;) {
        /* 不允许就等着, 每秒看一眼 —— 绝不主动去连设备 */
        if (!ts_allowed()) {
            Sleep(500);
            continue;
        }

        /* 已经写过且没到 5 小时: 继续等 */
        if (done_once && GetTickCount64() - last < 5ULL * 3600 * 1000) {
            Sleep(500);
            continue;
        }

        if (ble_timesync_once() == 0) {
            last = GetTickCount64();
            done_once = TRUE;
            air_log("对时: 写入成功");
            PostMessageW(ui, WM_APP_BLE, 3, 0);
        } else {
            air_log("对时: 写入失败, 5 分钟后再试");
            /* 失败退避, 避免反复连设备 */
            for (int s = 0; s < 300; s++) {
                if (!ts_allowed()) break;
                Sleep(1000);
            }
        }
    }
    return 0;
}

void timesync_start(HWND ui)
{
    CreateThread(NULL, 0, timesync_thread, ui, 0, NULL);
}
