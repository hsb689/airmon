/*
 * notify.c - 系统通知 (断开 / 重连时提示)
 *
 * 两条路, 按可靠性依次尝试:
 *   1. WinRT Toast  —— 真正的系统通知, 进操作中心, 不依赖托盘图标
 *   2. 托盘气泡     —— Shell_NotifyIcon(NIF_INFO), 需要托盘图标存在
 *
 * 非打包桌面应用用 Toast 有个前提: AppUserModelID 必须在开始菜单里有对应
 * 快捷方式(带 PKEY_AppUserModel_ID), 否则 CreateToastNotifier 会失败。
 * 所以这里首次需要时会创建一次快捷方式, 之后复用。
 *
 * 槽位(均含 0-5 IInspectable, 取自 windows-0.61.3 ABI 定义):
 *   IToastNotificationManagerStatics: CreateToastNotifier=6 CreateToastNotifierWithId=7
 *   IToastNotifier: Show=6 Hide=7
 *   IToastNotificationFactory: CreateToastNotification=6
 *   IXmlDocumentIO: LoadXml=6
 */
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winstring.h>
#include <objbase.h>
#include <roapi.h>
#include <shlobj.h>
#include <stdio.h>
#include <string.h>
#include "airmon.h"

/* ---------------- 接口 GUID ---------------- */
static const IID IID_IToastNotificationManagerStatics_ =
    {0x50ac103f,0xd235,0x4598,{0xbb,0xef,0x98,0xfe,0x4d,0x1a,0x3a,0xd4}};
static const IID IID_IToastNotificationFactory_ =
    {0x04124b20,0x82c6,0x4229,{0xb1,0x09,0xfd,0x9e,0xd4,0x66,0x2b,0x53}};
static const IID IID_IXmlDocumentIO_ =
    {0x6cd0e74e,0xee65,0x4489,{0x9e,0xbf,0xca,0x43,0xe8,0x7b,0xa6,0x37}};

/* 快捷方式相关 (本地定义, 免得依赖 libuuid) */
static const CLSID CLSID_ShellLink_ =
    {0x00021401,0x0000,0x0000,{0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}};
static const IID IID_IShellLinkW_ =
    {0x000214F9,0x0000,0x0000,{0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}};
static const IID IID_IPersistFile_ =
    {0x0000010B,0x0000,0x0000,{0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}};
static const IID IID_IPropertyStore_ =
    {0x886D8EEB,0x8CF2,0x4446,{0x8D,0x02,0xCD,0xBA,0x1D,0xBD,0xCF,0x99}};
/* PKEY_AppUserModel_ID = {9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3}, 5 */
static const PROPERTYKEY PKEY_AUMID_ =
    {{0x9F4C2855,0x9F79,0x4B39,{0xA8,0xD0,0xE1,0xD4,0x2D,0xE1,0xD5,0xF3}}, 5};

static const WCHAR CLASS_TOASTMGR[] = L"Windows.UI.Notifications.ToastNotificationManager";
static const WCHAR CLASS_TOAST[]    = L"Windows.UI.Notifications.ToastNotification";
static const WCHAR CLASS_XMLDOC[]   = L"Windows.Data.Xml.Dom.XmlDocument";

/* AUMID: 桌面应用用它标识通知来源 */
static const WCHAR AUMID[] = L"AirMon.AirQuality.Monitor";

/* ---------------- 槽位调用 ---------------- */
#define VFN(obj, slot, type) ((type)(*(void***)(obj))[(slot)])

typedef HRESULT (STDMETHODCALLTYPE *PFN_create_notifier_id)(void*, HSTRING, void**);
typedef HRESULT (STDMETHODCALLTYPE *PFN_show)(void*, void*);
typedef HRESULT (STDMETHODCALLTYPE *PFN_create_toast)(void*, void*, void**);
typedef HRESULT (STDMETHODCALLTYPE *PFN_load_xml)(void*, HSTRING);

static ULONG rel2(IUnknown* p) { return p ? p->lpVtbl->Release(p) : 0; }

/* ---------------- 开始菜单快捷方式(带 AUMID) ---------------- */
/* 只建一次; 已存在就不动 */
static void ensure_shortcut(void)
{
    WCHAR lnk[MAX_PATH] = {0};
    WCHAR exe[MAX_PATH] = {0};

    if (FAILED(SHGetFolderPathW(NULL, CSIDL_PROGRAMS, NULL, 0, lnk))) return;
    lstrcpynW(lnk + lstrlenW(lnk), L"\\AirMon.lnk", MAX_PATH - lstrlenW(lnk));
    if (GetFileAttributesW(lnk) != INVALID_FILE_ATTRIBUTES) return;   /* 已存在 */

    GetModuleFileNameW(NULL, exe, MAX_PATH);

    {
        IShellLinkW* link = NULL;
        HRESULT hr = CoCreateInstance(&CLSID_ShellLink_, NULL, CLSCTX_INPROC_SERVER,
                                      &IID_IShellLinkW_, (void**)&link);
        if (FAILED(hr) || !link) return;

        link->lpVtbl->SetPath(link, exe);
        link->lpVtbl->SetDescription(link, L"AirMon 空气质量监测");

        {
            /* 把 AUMID 写进快捷方式, Toast 才认。
               注意: PROPVARIANT 里的字符串必须是自己分配的(SHStrDupW),
               否则 PropVariantClear 会去释放静态常量, 直接堆损坏崩溃。 */
            IPropertyStore* ps = NULL;
            if (SUCCEEDED(link->lpVtbl->QueryInterface(link, &IID_IPropertyStore_,
                                                       (void**)&ps)) && ps) {
                PROPVARIANT pv;
                PropVariantInit(&pv);
                pv.vt = VT_LPWSTR;
                /* 自己 CoTaskMemAlloc 一份: PropVariantClear 会按 CoTaskMemFree 释放,
                   不能直接挂静态字符串(否则堆损坏) */
                {
                    SIZE_T cb = (lstrlenW(AUMID) + 1) * sizeof(WCHAR);
                    pv.pwszVal = (LPWSTR)CoTaskMemAlloc(cb);
                    if (pv.pwszVal) {
                        memcpy(pv.pwszVal, AUMID, cb);
                        ps->lpVtbl->SetValue(ps, &PKEY_AUMID_, &pv);
                        ps->lpVtbl->Commit(ps);
                    }
                }
                PropVariantClear(&pv);
                ps->lpVtbl->Release(ps);
            }
        }
        {
            IPersistFile* pf = NULL;
            if (SUCCEEDED(link->lpVtbl->QueryInterface(link, &IID_IPersistFile_,
                                                       (void**)&pf)) && pf) {
                pf->lpVtbl->Save(pf, lnk, TRUE);
                pf->lpVtbl->Release(pf);
            }
        }
        link->lpVtbl->Release(link);
    }
}

/* ---------------- Toast ---------------- */
static BOOL toast_show(const WCHAR* title, const WCHAR* body)
{
    HSTRING hcls_mgr = NULL, hcls_toast = NULL, hcls_xml = NULL;
    HSTRING hxml = NULL, haumid = NULL;
    IInspectable* inst = NULL;
    void* notifier = NULL;
    void* xmldoc = NULL;
    void* toast = NULL;
    BOOL ok = FALSE;
    HRESULT hr;
    WCHAR xml[1024];

    /* 标题/正文都是固定文案, 不含 XML 特殊字符 */
    swprintf(xml, ARRAYSIZE(xml),
             L"<toast><visual><binding template=\"ToastGeneric\">"
             L"<text>%s</text><text>%s</text>"
             L"</binding></visual></toast>",
             title, body);

    if (FAILED(WindowsCreateString(CLASS_XMLDOC, (UINT32)lstrlenW(CLASS_XMLDOC), &hcls_xml))) goto done;
    if (FAILED(WindowsCreateString(xml, (UINT32)lstrlenW(xml), &hxml))) goto done;
    if (FAILED(WindowsCreateString(CLASS_TOASTMGR, (UINT32)lstrlenW(CLASS_TOASTMGR), &hcls_mgr))) goto done;
    if (FAILED(WindowsCreateString(CLASS_TOAST, (UINT32)lstrlenW(CLASS_TOAST), &hcls_toast))) goto done;
    if (FAILED(WindowsCreateString(AUMID, (UINT32)lstrlenW(AUMID), &haumid))) goto done;

    /* --- 1. XmlDocument.LoadXml --- */
    if (FAILED(RoActivateInstance(hcls_xml, &inst)) || !inst) goto done;
    if (FAILED(((IUnknown*)inst)->lpVtbl->QueryInterface((IUnknown*)inst,
                &IID_IXmlDocumentIO_, &xmldoc)) || !xmldoc) goto done;
    rel2((IUnknown*)inst); inst = NULL;
    if (FAILED(VFN(xmldoc, 6, PFN_load_xml)(xmldoc, hxml))) goto done;

    /* --- 2. ToastNotification.CreateToastNotification(xml) --- */
    {
        IInspectable* fac = NULL;
        if (FAILED(RoGetActivationFactory(hcls_toast, &IID_IToastNotificationFactory_,
                                          (void**)&fac)) || !fac) goto done;
        hr = VFN(fac, 6, PFN_create_toast)(fac, xmldoc, &toast);
        rel2((IUnknown*)fac);
        if (FAILED(hr) || !toast) goto done;
    }

    /* --- 3. ToastNotifier.Show(toast) --- */
    {
        IInspectable* fac = NULL;
        if (FAILED(RoGetActivationFactory(hcls_mgr, &IID_IToastNotificationManagerStatics_,
                                          (void**)&fac)) || !fac) goto done;
        /* 带 AUMID 的版本(槽 7) */
        hr = VFN(fac, 7, PFN_create_notifier_id)(fac, haumid, &notifier);
        rel2((IUnknown*)fac);
        if (FAILED(hr) || !notifier) goto done;
    }
    ok = SUCCEEDED(VFN(notifier, 6, PFN_show)(notifier, toast)) ? TRUE : FALSE;

done:
    if (toast)    rel2((IUnknown*)toast);
    if (xmldoc)   rel2((IUnknown*)xmldoc);
    if (notifier) rel2((IUnknown*)notifier);
    if (inst)     rel2((IUnknown*)inst);
    if (hxml)     WindowsDeleteString(hxml);
    if (haumid)   WindowsDeleteString(haumid);
    if (hcls_mgr) WindowsDeleteString(hcls_mgr);
    if (hcls_toast) WindowsDeleteString(hcls_toast);
    if (hcls_xml) WindowsDeleteString(hcls_xml);
    return ok;
}

/* ---------------- 对外接口 ---------------- */
/* 发一条系统通知; TRUE=Toast 成功, FALSE=需要调用方兜底(托盘气泡) */
BOOL notify_toast(const WCHAR* title, const WCHAR* body)
{
    HRESULT hrCo = RoInitialize(RO_INIT_MULTITHREADED);
    BOOL ok;

    if (FAILED(hrCo) && hrCo != RPC_E_CHANGED_MODE) return FALSE;

    ensure_shortcut();
    ok = toast_show(title, body);

    if (SUCCEEDED(hrCo)) RoUninitialize();   /* 自己初始化的才反初始化 */
    return ok;
}
