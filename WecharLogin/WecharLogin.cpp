#include "WxLoginClient.h"
#include <winhttp.h>
#include <wincodec.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <ctime>
#include <cstdio>
#include <cwchar>

#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "windowscodecs.lib")
#pragma comment(lib, "ole32.lib")


// ---- 共享 AES Key（32 字节）和签名 Secret（要和服务端 CryptoCfg 一致）
void GetAesKey(BYTE out[32])
{
    

    // ★ 拆分存储：逆向者看不出来你真实 key 是什么
    static const BYTE part1[16] =
    {
        0x10 ^ 0xA5,0x23 ^ 0xA5,0x45 ^ 0xA5,0x67 ^ 0xA5,
        0x89 ^ 0xA5,0xAB ^ 0xA5,0xCD ^ 0xA5,0xEF ^ 0xA5,
        0x01 ^ 0xA5,0x12 ^ 0xA5,0x23 ^ 0xA5,0x34 ^ 0xA5,
        0x45 ^ 0xA5,0x56 ^ 0xA5,0x67 ^ 0xA5,0x78 ^ 0xA5
    };

    static const BYTE part2[16] =
    {
        0x99 ^ 0x5A,0xAA ^ 0x5A,0xBB ^ 0x5A,0xCC ^ 0x5A,
        0xDD ^ 0x5A,0xEE ^ 0x5A,0xFF ^ 0x5A,0x00 ^ 0x5A,
        0x13 ^ 0x5A,0x57 ^ 0x5A,0x9B ^ 0x5A,0xDF ^ 0x5A,
        0x24 ^ 0x5A,0x68 ^ 0x5A,0xAC ^ 0x5A,0xF0 ^ 0x5A
    };

    // ★ 运行时恢复真正 key
    for (int i = 0; i < 16; i++)
    {
        out[i] = part1[i] ^ 0xA5;
        out[i + 16] = part2[i] ^ 0x5A;
    }

    
}
// 签名密钥（HMAC-SHA256 用）必须和服务端一致
static const char g_SigSecret[] = "32位随机密钥";

// ======================= 全局 QR 资源 & 窗口句柄 =========================
static HBITMAP g_hQrBitmap = NULL;
static int     g_bmW = 0;
static int     g_bmH = 0;
static HWND    g_hQrWnd = NULL;

// 自定义消息：扫码完成后关闭窗口
const UINT WM_QR_LOGIN_DONE = WM_APP + 1;

// ======================= 配置区 =========================
static wchar_t g_BackendBase[256] = L"http://0.0.0.0:8080";  // 默认后端地址

void WxLogin_SetBackendBase(const wchar_t* baseUrl)
{
    if (!baseUrl) return;
    wcsncpy_s(g_BackendBase, baseUrl, _TRUNCATE);
}

// -----------------------------
// UTF8 / WIDE 转换
// -----------------------------
static int Utf8ToWide(const char* s, wchar_t* w, int c)
{
   
    if (!s || !w || c <= 0) { return 0; }
    int ret = MultiByteToWideChar(CP_UTF8, 0, s, -1, w, c);
    
    return ret;
}

static int WideToUtf8(const wchar_t* w, char* s, int c)
{
   
    if (!w || !s || c <= 0) { return 0; }
    int ret = WideCharToMultiByte(CP_UTF8, 0, w, -1, s, c, NULL, NULL);
    
    return ret;
}

// ====================== Base64 编码 ======================
static bool Base64Encode(const BYTE* data, DWORD dataLen, std::string& out)
{
    
    if (!data || dataLen == 0) { return false; }

    DWORD dwLen = 0;
    if (!CryptBinaryToStringA(
        data,
        dataLen,
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        nullptr,
        &dwLen))
    {

        return false;
    }

    if (dwLen == 0) { return false; }

    std::string tmp;
    tmp.resize(dwLen);

    if (!CryptBinaryToStringA(
        data,
        dataLen,
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        (LPSTR)&tmp[0],
        &dwLen))
    {

        return false;
    }

    if (dwLen > 0 && tmp[dwLen - 1] == '\0')
        tmp.resize(dwLen - 1);
    else
        tmp.resize(dwLen);

    out.swap(tmp);
    
    return true;
}

// ====================== 随机 IV ======================
static bool GenRandomBytes(BYTE* buf, DWORD len)
{
   
    if (!buf || !len) { return false; }
    NTSTATUS st = BCryptGenRandom(nullptr, buf, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    
    return (st >= 0);
}

// ====================== AES-256-CBC + PKCS7 加密 ======================
static bool AesEncryptCbcPkcs7(
    const BYTE* plain, DWORD plainLen,
    const BYTE* key32,
    const BYTE* iv16,
    std::vector<BYTE>& outCipher)
{
    
    if (!plain || !plainLen || !key32 || !iv16) { return false; }

    NTSTATUS status = 0;
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    PBYTE pbKeyObject = nullptr;
    DWORD cbKeyObject = 0, cbData = 0, cbCipher = 0;
    bool ok = false;

    BYTE ivLocal[16];
    memcpy(ivLocal, iv16, 16);

    do
    {
        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (status < 0) break;

        status = BCryptSetProperty(
            hAlg,
            BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
            (ULONG)sizeof(BCRYPT_CHAIN_MODE_CBC),
            0);
        if (status < 0) break;

        status = BCryptGetProperty(
            hAlg,
            BCRYPT_OBJECT_LENGTH,
            (PUCHAR)&cbKeyObject,
            sizeof(DWORD),
            &cbData,
            0);
        if (status < 0 || cbKeyObject == 0) break;

        pbKeyObject = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
        if (!pbKeyObject) break;

        status = BCryptGenerateSymmetricKey(
            hAlg,
            &hKey,
            pbKeyObject,
            cbKeyObject,
            (PUCHAR)key32,
            32,
            0);
        if (status < 0) break;

        // 探测长度
        status = BCryptEncrypt(
            hKey,
            (PUCHAR)plain,
            plainLen,
            nullptr,
            ivLocal,
            sizeof(ivLocal),
            nullptr,
            0,
            &cbCipher,
            BCRYPT_BLOCK_PADDING);
        if (status < 0) break;

        outCipher.resize(cbCipher);

        // 真正加密
        memcpy(ivLocal, iv16, 16);
        status = BCryptEncrypt(
            hKey,
            (PUCHAR)plain,
            plainLen,
            nullptr,
            ivLocal,
            sizeof(ivLocal),
            outCipher.data(),
            cbCipher,
            &cbCipher,
            BCRYPT_BLOCK_PADDING);
        if (status < 0) break;

        ok = true;

    } while (false);

    if (hKey) BCryptDestroyKey(hKey);
    if (pbKeyObject) HeapFree(GetProcessHeap(), 0, pbKeyObject);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!ok)
        outCipher.clear();

    
    return ok;
}

// ====================== HMAC-SHA256 → Hex ======================
static bool HmacSha256Hex(
    const std::string& data,
    const BYTE* key,
    DWORD keyLen,
    std::string& outHex)
{
    
    NTSTATUS status = 0;
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    PBYTE pbHashObject = nullptr;
    DWORD cbHashObject = 0, cbData = 0, cbHash = 0;
    std::vector<BYTE> hashBuf;
    bool ok = false;

    do
    {
        status = BCryptOpenAlgorithmProvider(
            &hAlg,
            BCRYPT_SHA256_ALGORITHM,
            nullptr,
            BCRYPT_ALG_HANDLE_HMAC_FLAG);
        if (status < 0) break;

        status = BCryptGetProperty(
            hAlg,
            BCRYPT_OBJECT_LENGTH,
            (PUCHAR)&cbHashObject,
            sizeof(DWORD),
            &cbData,
            0);
        if (status < 0 || cbHashObject == 0) break;

        pbHashObject = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
        if (!pbHashObject) break;

        status = BCryptGetProperty(
            hAlg,
            BCRYPT_HASH_LENGTH,
            (PUCHAR)&cbHash,
            sizeof(DWORD),
            &cbData,
            0);
        if (status < 0 || cbHash == 0) break;

        status = BCryptCreateHash(
            hAlg,
            &hHash,
            pbHashObject,
            cbHashObject,
            (PUCHAR)key,
            keyLen,
            0);
        if (status < 0) break;

        status = BCryptHashData(
            hHash,
            (PUCHAR)data.data(),
            (ULONG)data.size(),
            0);
        if (status < 0) break;

        hashBuf.resize(cbHash);
        status = BCryptFinishHash(
            hHash,
            hashBuf.data(),
            cbHash,
            0);
        if (status < 0) break;

        static const char* hex = "0123456789ABCDEF";
        std::string tmp;
        tmp.resize(cbHash * 2);
        for (DWORD i = 0; i < cbHash; ++i)
        {
            tmp[i * 2 + 0] = hex[(hashBuf[i] >> 4) & 0x0F];
            tmp[i * 2 + 1] = hex[(hashBuf[i]) & 0x0F];
        }
        outHex.swap(tmp);
        ok = true;

    } while (false);

    if (hHash) BCryptDestroyHash(hHash);
    if (pbHashObject) HeapFree(GetProcessHeap(), 0, pbHashObject);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);

    
    return ok;
}

// ====================== 构造加密信封 JSON ======================
static bool BuildSecureEnvelopeJson(
    const char* innerJson,
    char* outBuf,
    size_t outBufSize)
{
    
    if (!innerJson || !outBuf || outBufSize == 0) { return false; }

    const BYTE* plain = (const BYTE*)innerJson;
    DWORD       plainLen = (DWORD)strlen(innerJson);

    BYTE iv[16];
    if (!GenRandomBytes(iv, sizeof(iv))) { return false; }

    BYTE aesKey[32] = { 0 };
    GetAesKey(aesKey);

    std::vector<BYTE> cipher;
    if (!AesEncryptCbcPkcs7(plain, plainLen, aesKey, iv, cipher))
    {
        SecureZeroMemory(aesKey, sizeof(aesKey));
        return false;
    }

    SecureZeroMemory(aesKey, sizeof(aesKey));


    std::string payloadB64;
    std::string ivB64;
    if (!Base64Encode(cipher.data(), (DWORD)cipher.size(), payloadB64)) { return false; }
    if (!Base64Encode(iv, sizeof(iv), ivB64)) { return false; }

    std::time_t ts = std::time(nullptr);
    char tsBuf[32];
    std::snprintf(tsBuf, sizeof(tsBuf), "%lld", (long long)ts);

    std::string raw = ivB64;
    raw.push_back('|');
    raw += payloadB64;
    raw.push_back('|');
    raw += tsBuf;

    std::string sigHex;
    if (!HmacSha256Hex(raw, (const BYTE*)g_SigSecret, (DWORD)strlen(g_SigSecret), sigHex))
    {

        return false;
    }

    int n = std::snprintf(
        outBuf,
        outBufSize,
        "{\"payload\":\"%s\",\"iv\":\"%s\",\"ts\":%s,\"sig\":\"%s\"}",
        payloadB64.c_str(),
        ivB64.c_str(),
        tsBuf,
        sigHex.c_str()
    );
    if (n <= 0 || (size_t)n >= outBufSize)
    {

        return false;
    }

    
    return true;
}

// ======================================================
//  PNG -> HBITMAP
// ======================================================
static HRESULT PngBytesToHBITMAP(const BYTE* data, DWORD len, HBITMAP* phBmp, int* pw, int* ph)
{
  
    if (!data || !len || !phBmp) {

        return E_INVALIDARG;
    }

    *phBmp = NULL;
    if (pw) *pw = 0;
    if (ph) *ph = 0;

    IWICImagingFactory* pFactory = NULL;
    IWICStream* pStream = NULL;
    IWICBitmapDecoder* pDecoder = NULL;
    IWICBitmapFrameDecode* pFrame = NULL;
    IWICFormatConverter* pConverter = NULL;
    HRESULT hr = S_OK;

    UINT    w = 0, h = 0;
    BITMAPINFO bi;
    ZeroMemory(&bi, sizeof(bi));
    VOID* bits = NULL;
    HDC     hdc = NULL;
    HBITMAP hBmp = NULL;
    UINT    stride = 0;
    UINT    bufSize = 0;

    do
    {
        hr = CoCreateInstance(
            CLSID_WICImagingFactory,
            NULL,
            CLSCTX_INPROC_SERVER,
            IID_IWICImagingFactory,
            (void**)&pFactory);
        if (FAILED(hr)) break;

        hr = pFactory->CreateStream(&pStream);
        if (FAILED(hr)) break;

        hr = pStream->InitializeFromMemory((WICInProcPointer)data, len);
        if (FAILED(hr)) break;

        hr = pFactory->CreateDecoderFromStream(
            pStream,
            NULL,
            WICDecodeMetadataCacheOnLoad,
            &pDecoder);
        if (FAILED(hr)) break;

        hr = pDecoder->GetFrame(0, &pFrame);
        if (FAILED(hr)) break;

        hr = pFactory->CreateFormatConverter(&pConverter);
        if (FAILED(hr)) break;

        hr = pConverter->Initialize(
            pFrame,
            GUID_WICPixelFormat32bppBGRA,
            WICBitmapDitherTypeNone,
            NULL,
            0.0,
            WICBitmapPaletteTypeCustom);
        if (FAILED(hr)) break;

        hr = pConverter->GetSize(&w, &h);
        if (FAILED(hr)) break;

        ZeroMemory(&bi, sizeof(bi));
        bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bi.bmiHeader.biWidth = (LONG)w;
        bi.bmiHeader.biHeight = -(LONG)h;
        bi.bmiHeader.biPlanes = 1;
        bi.bmiHeader.biBitCount = 32;
        bi.bmiHeader.biCompression = BI_RGB;

        hdc = GetDC(NULL);
        hBmp = CreateDIBSection(hdc, &bi, DIB_RGB_COLORS, &bits, NULL, 0);
        ReleaseDC(NULL, hdc);
        hdc = NULL;

        if (!hBmp || !bits) {
            hr = E_OUTOFMEMORY;
            break;
        }

        stride = w * 4;
        bufSize = stride * h;
        hr = pConverter->CopyPixels(NULL, stride, bufSize, (BYTE*)bits);
        if (FAILED(hr)) break;

        *phBmp = hBmp;
        if (pw) *pw = (int)w;
        if (ph) *ph = (int)h;

    } while (0);

    if (FAILED(hr))
    {
        if (hBmp) DeleteObject(hBmp);
        if (phBmp) *phBmp = NULL;
        if (pw) *pw = 0;
        if (ph) *ph = 0;
    }

    if (pConverter) pConverter->Release();
    if (pFrame)     pFrame->Release();
    if (pDecoder)   pDecoder->Release();
    if (pStream)    pStream->Release();
    if (pFactory)   pFactory->Release();

    
    return hr;
}

static BOOL GetJsonString(const char* json, const char* key, char* out, int outSize, BOOL unescapeSlash)
{
   
    if (!json || !key || !out || outSize <= 1) { return FALSE; }

    // 只找 "key"，不带冒号，兼容 "key": 和 "key" : 两种写法
    char pattern[64] = { 0 };
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char* p = strstr(json, pattern);
    if (!p) { return FALSE; }

    // 跳过 "key"
    p += strlen(pattern);

    // 跳过空白，直到冒号
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') ++p;
    if (*p != ':') { return FALSE; }
    ++p;

    // 冒号后的空白
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') ++p;

    // 必须是字符串："xxxx"
    if (*p != '"') { return FALSE; }
    ++p;

    const char* e = p;
    while (*e && *e != '"') ++e;

    int len = (int)(e - p);
    if (len <= 0) { return FALSE; }
    if (len >= outSize) len = outSize - 1;

    int oi = 0;
    for (int i = 0; i < len && oi < outSize - 1; ++i)
    {
        if (unescapeSlash && p[i] == '\\' && i + 1 < len && p[i + 1] == '/')
        {
            out[oi++] = '/';
            ++i;
        }
        else
        {
            out[oi++] = p[i];
        }
    }
    out[oi] = 0;

    
    return TRUE;
}


static BOOL ParseJsonBool(const char* json, const char* key, BOOL* out)
{
    
    if (!json || !key || !out) { return FALSE; }

    // 同样先找 "key"（不带冒号）
    char pattern[64] = { 0 };
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char* p = strstr(json, pattern);
    if (!p) { return FALSE; }

    // 跳过 "key"
    p += strlen(pattern);

    // 跳过空白，到冒号
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') ++p;
    if (*p != ':') { return FALSE; }
    ++p;

    // 再跳过冒号后的空白
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') ++p;

    // 兼容 success:true / success: false
    if (strncmp(p, "true", 4) == 0)
    {
        *out = TRUE;

        return TRUE;
    }
    if (strncmp(p, "false", 5) == 0)
    {
        *out = FALSE;

        return TRUE;
    }

    // 也兼容 "true" / "false"
    if (*p == '"')
    {
        ++p;
        if (strncmp(p, "true", 4) == 0)
        {
            *out = TRUE;

            return TRUE;
        }
        if (strncmp(p, "false", 5) == 0)
        {
            *out = FALSE;

            return TRUE;
        }
    }

    
    return FALSE;
}


static BOOL ParseJsonString(const char* json, const char* key, wchar_t* out, int cch)
{
   
    if (!json || !key || !out || cch <= 0) { return FALSE; }
    char buf[256] = { 0 };
    if (!GetJsonString(json, key, buf, sizeof(buf), FALSE)) { return FALSE; }
    int ok = Utf8ToWide(buf, out, cch) > 0;
    
    return ok;
}

// -----------------------------
// HTTP 封装 (WinHTTP)
// -----------------------------
static BOOL HttpRequest(
    const wchar_t* method,
    const wchar_t* url,
    const wchar_t* headers,
    const void* body, DWORD bodyLen,
    BYTE** ppData, DWORD* pDataLen)
{
   
    if (!method || !url || !ppData || !pDataLen) { return FALSE; }
    *ppData = NULL; *pDataLen = 0;

    BOOL ok = FALSE;
    HINTERNET s = NULL, c = NULL, r = NULL;
    BYTE* buf = NULL; DWORD total = 0;
    wchar_t host[256] = { 0 }, path[2048] = { 0 };
    INTERNET_PORT port = 0; BOOL https = FALSE; DWORD hdrLen = 0;
    URL_COMPONENTS uc; ZeroMemory(&uc, sizeof(uc));
    uc.dwStructSize = sizeof(uc);
    uc.dwSchemeLength = (DWORD)-1;
    uc.dwHostNameLength = (DWORD)-1;
    uc.dwUrlPathLength = (DWORD)-1;
    uc.dwExtraInfoLength = (DWORD)-1;

    do {
        s = WinHttpOpen(L"WxWeGameConsole/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0);
        if (!s) break;

        if (!WinHttpCrackUrl(url, 0, 0, &uc)) break;

        wcsncpy_s(host, 256, uc.lpszHostName, uc.dwHostNameLength);
        port = uc.nPort;
        https = (uc.nScheme == INTERNET_SCHEME_HTTPS);

        c = WinHttpConnect(s, host, port, 0);
        if (!c) break;

        wcsncpy_s(path, 2048, uc.lpszUrlPath, uc.dwUrlPathLength);
        if (uc.dwExtraInfoLength)
            wcsncat_s(path, 2048, uc.lpszExtraInfo, uc.dwExtraInfoLength);

        r = WinHttpOpenRequest(
            c,
            method,
            path,
            NULL,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            https ? WINHTTP_FLAG_SECURE : 0);
        if (!r) break;

        hdrLen = headers ? (DWORD)wcslen(headers) : 0;

        if (!WinHttpSendRequest(
            r,
            headers ? headers : WINHTTP_NO_ADDITIONAL_HEADERS,
            hdrLen,
            (LPVOID)body,
            bodyLen,
            bodyLen,
            0)) break;

        if (!WinHttpReceiveResponse(r, NULL)) break;

        for (;;)
        {
            DWORD sz = 0;
            if (!WinHttpQueryDataAvailable(r, &sz) || !sz) break;

            BYTE* nb = (BYTE*)realloc(buf, total + sz + 1);
            if (!nb) { ok = FALSE; break; }
            buf = nb;

            DWORD rd = 0;
            if (!WinHttpReadData(r, buf + total, sz, &rd)) { ok = FALSE; break; }

            total += rd;
        }

        if (!buf) { ok = FALSE; break; }

        buf[total] = 0;
        *ppData = buf;
        *pDataLen = total;
        buf = NULL;
        ok = TRUE;

    } while (0);

    if (!ok && buf) free(buf);
    if (r) WinHttpCloseHandle(r);
    if (c) WinHttpCloseHandle(c);
    if (s) WinHttpCloseHandle(s);

    
    return ok;
}

#define HttpGet(u,pp,pl)  HttpRequest(L"GET",(u),NULL,NULL,0,(pp),(pl))

// ------------------------------------------------------
// 从 WeGame 登录页 HTML 解析 uuid
// ------------------------------------------------------
static BOOL GetUuid(wchar_t* uuidW, int cch)
{
    
    if (!uuidW || cch <= 1) { return FALSE; }

    const wchar_t* url =
        L"https://open.weixin.qq.com/connect/qrconnect?"
        L"appid=wx911818d5d92affa8&scope=snsapi_login&"
        L"redirect_uri=https://www.wegame.com.cn/login/callback.html?t=wx&c=0&a=0&"
        L"login_type=jssdk&self_redirect=true&state=dc30dd59&style=black&"
        L"href=https://wegame.gtimg.com/g.55555-r.c4663/login/qrcode.css";

    BYTE* p = NULL; DWORD n = 0;
    if (!HttpGet(url, &p, &n) || !p) { return FALSE; }

    const char* body = (const char*)p;
    const char* x = strstr(body, "uuid=");
    if (!x) { free(p);  return FALSE; }

    x += 5;
    const char* e = x;
    while (*e && *e != '\"' && *e != '\'' && *e != '&'
        && *e != '\r' && *e != '\n' && *e != ' ') ++e;

    int len = (int)(e - x);
    if (len <= 0 || len >= 64) { free(p); return FALSE; }

    char uuidA[64] = { 0 };
    memcpy(uuidA, x, len);
    uuidA[len] = 0;

    Utf8ToWide(uuidA, uuidW, cch);
    free(p);
    
    return TRUE;
}

// ------------------------------------------------------
// 解析 wx_code
// ------------------------------------------------------
static BOOL ParseWxCode(BYTE* data, char* out, int outSize)
{
   
    if (!data || !out || outSize <= 1) { return FALSE; }
    const char* body = (const char*)data;

    const char* k1 = "\"wx_code\":\"";
    const char* k2 = "window.wx_code=\"";
    const char* k3 = "window.wx_code='";

    const char* p = strstr(body, k1);
    if (p) p += strlen(k1);
    else if ((p = strstr(body, k2))) p += strlen(k2);
    else if ((p = strstr(body, k3))) p += strlen(k3);
    else { return FALSE; }

    const char* e = p;
    while (*e && *e != '\"' && *e != '\'' && *e != ';'
        && *e != '\r' && *e != '\n') ++e;

    int len = (int)(e - p);
    if (len <= 0 || len >= outSize) { return FALSE; }

    memcpy(out, p, len);
    out[len] = 0;
    
    return TRUE;
}

// ------------------------------------------------------
// 解析 JSON: openid / nick
// ------------------------------------------------------
static BOOL ExtractOpenId(const char* json, wchar_t* out, int outSize)
{
   
    if (!json || !out || outSize <= 1) { return FALSE; }
    char buf[128] = { 0 };
    if (!GetJsonString(json, "openid", buf, sizeof(buf), FALSE)) { return FALSE; }
    BOOL ok = Utf8ToWide(buf, out, outSize) > 0;
    
    return ok;
}

static BOOL ExtractNick(const char* json, wchar_t* out, int outSize)
{
   
    if (!json || !out || outSize <= 1) { return FALSE; }
    char buf[256] = { 0 };
    if (!GetJsonString(json, "nick", buf, sizeof(buf), TRUE)) { return FALSE; }
    BOOL ok = Utf8ToWide(buf, out, outSize) > 0;
    
    return ok;
}

// ------------------------------------------------------
// 轮询 uuid -> wx_code
// ------------------------------------------------------
static BOOL PollWxCode(const wchar_t* uuidW, wchar_t* wxCode, int cch)
{
   
    if (!uuidW || !wxCode || cch <= 1) { return FALSE; }

    wchar_t url[512];
    wsprintfW(url, L"https://lp.open.weixin.qq.com/connect/l/qrconnect?uuid=%s", uuidW);

    char codeA[128] = { 0 };

    for (int i = 0; i < 120; ++i) {
        BYTE* p = NULL; DWORD n = 0;
        if (HttpGet(url, &p, &n) && p) {
            BOOL ok = ParseWxCode(p, codeA, sizeof(codeA));
            free(p);
            if (ok) {
                Utf8ToWide(codeA, wxCode, cch);

                return TRUE;
            }
        }
        Sleep(1500);
    }
    
    return FALSE;
}

// ------------------------------------------------------
// 全局微信登录结果（内部用）
// ------------------------------------------------------
static wchar_t g_szOpenId[128] = { 0 };
static wchar_t g_szNick[256] = { 0 };

// ------------------------------------------------------
// 调 WeGame 登录：只负责拿 openid + nick
// ------------------------------------------------------
static BOOL WeGameLogin(const wchar_t* wxCode)
{
   
    if (!wxCode || !*wxCode) { return FALSE; }

    char codeA[128] = { 0 };
    if (WideToUtf8(wxCode, codeA, sizeof(codeA)) <= 0) { return FALSE; }

    char jsonBody[512];
    int jlen = snprintf(
        jsonBody, sizeof(jsonBody),
        "{\"login_info\":{\"wx_info_type\":1,\"appid\":\"wx911818d5d92affa8\",\"code\":\"%s\"},"
        "\"config_params\":{\"lang_type\":0},"
        "\"mappid\":\"10001\",\"mcode\":\"\",\"clienttype\":\"1000005\"}",
        codeA);
    if (jlen <= 0 || jlen >= (int)sizeof(jsonBody)) { return FALSE; }

    const wchar_t* url =
        L"https://www.wegame.com.cn/api/middle/clientapi/auth/login_by_wechat";

    wchar_t hdr[512];
    wsprintfW(hdr,
        L"Connection: Keep-Alive\r\n"
        L"Content-Type: application/json; Charset=UTF-8\r\n"
        L"Accept: */*\r\n"
        L"Referer: https://www.wegame.com.cn/login/callback.html?t=wx&c=0&a=0&code=%s&state=1\r\n"
        L"Origin: https://www.wegame.com.cn\r\n",
        wxCode);

    BYTE* resp = NULL; DWORD n = 0;
    if (!HttpRequest(L"GET", url, hdr, jsonBody, (DWORD)jlen, &resp, &n) || !resp) {

        return FALSE;
    }

    const char* ja = (const char*)resp;

    wchar_t openidW[128] = { 0 };
    if (ExtractOpenId(ja, openidW, 128)) {
        wcsncpy_s(g_szOpenId, _countof(g_szOpenId), openidW, _TRUNCATE);
    }

    wchar_t nickW[256] = { 0 };
    if (ExtractNick(ja, nickW, _countof(nickW))) {
        wcsncpy_s(g_szNick, _countof(g_szNick), nickW, _TRUNCATE);
    }

    free(resp);
    
    return TRUE;
}

// ------------------------------------------------------
// 下载二维码并转成 HBITMAP
// ------------------------------------------------------
static BOOL GetQrBitmap(const wchar_t* uuidW)
{
    
    if (!uuidW || !*uuidW) { return FALSE; }

    wchar_t url[256];
    wsprintfW(url, L"https://open.weixin.qq.com/connect/qrcode/%s", uuidW);

    BYTE* data = NULL; DWORD len = 0;
    if (!HttpGet(url, &data, &len) || !data) { return FALSE; }

    HBITMAP bmp = NULL; int w = 0, h = 0;
    HRESULT hr = PngBytesToHBITMAP(data, len, &bmp, &w, &h);
    free(data);

    if (FAILED(hr) || !bmp) { return FALSE; }

    if (g_hQrBitmap) DeleteObject(g_hQrBitmap);
    g_hQrBitmap = bmp;
    g_bmW = w;
    g_bmH = h;

    
    return TRUE;
}

// ------------------------------------------------------
// 二维码窗口 WndProc
// ------------------------------------------------------
static LRESULT CALLBACK QrWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);

        RECT rc;
        GetClientRect(hWnd, &rc);
        FillRect(hdc, &rc, (HBRUSH)(COLOR_WINDOW + 1));

        if (g_hQrBitmap)
        {
            HDC hMem = CreateCompatibleDC(hdc);
            HBITMAP hOld = (HBITMAP)SelectObject(hMem, g_hQrBitmap);

            int qrSize = min(rc.right - rc.left - 40, rc.bottom - rc.top - 80);
            int x = (rc.right - rc.left - qrSize) / 2;
            int y = (rc.bottom - rc.top - qrSize) / 2;

            SetStretchBltMode(hdc, HALFTONE);
            StretchBlt(
                hdc,
                x, y,
                qrSize, qrSize,
                hMem,
                0, 0,
                g_bmW, g_bmH,
                SRCCOPY
            );

            SelectObject(hMem, hOld);
            DeleteDC(hMem);
        }

        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, RGB(0, 0, 0));
        const wchar_t* tip = L"微信二维码登录";
        DrawTextW(hdc, tip, -1, &rc,
            DT_CENTER | DT_BOTTOM | DT_SINGLELINE);

        EndPaint(hWnd, &ps);

        return 0;
    }

    case WM_QR_LOGIN_DONE:
        DestroyWindow(hWnd);

        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);

        return 0;
    }

    
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ------------------------------------------------------
// 轮询线程：uuid -> wx_code -> WeGameLogin
// ------------------------------------------------------
static DWORD WINAPI WorkerThread(LPVOID lp)
{
   
    if (!lp) { return 0; }

    wchar_t uuid[64] = { 0 };
    wcsncpy_s(uuid, _countof(uuid), (wchar_t*)lp, _TRUNCATE);
    free(lp);

    wchar_t wxCode[128] = { 0 };
    if (!PollWxCode(uuid, wxCode, _countof(wxCode))) {
        if (g_hQrWnd)
            PostMessageW(g_hQrWnd, WM_QR_LOGIN_DONE, 0, 0);

        return 0;
    }

    if (g_hQrWnd)
        PostMessageW(g_hQrWnd, WM_QR_LOGIN_DONE, 0, 0);

    WeGameLogin(wxCode);
    
    return 0;
}

// ------------------------------------------------------
// 对外：二维码登录，拿 openid + nick
// ------------------------------------------------------
BOOL WxLogin_ShowQrAndGetOpenId(WxLoginResult* result)
{
   
    if (!result) { return FALSE; }

    ZeroMemory(result, sizeof(WxLoginResult));
    ZeroMemory(g_szOpenId, sizeof(g_szOpenId));
    ZeroMemory(g_szNick, sizeof(g_szNick));

    HRESULT hrCo = CoInitialize(NULL);
    if (FAILED(hrCo))
    {

        return FALSE;
    }

    wchar_t uuid[64] = { 0 };
    if (!GetUuid(uuid, _countof(uuid))) {
        CoUninitialize();

        return FALSE;
    }

    if (!GetQrBitmap(uuid)) {
        CoUninitialize();

        return FALSE;
    }

    WNDCLASSW wc = {};
    wc.lpfnWndProc = QrWndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"QrWindowClass";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassW(&wc);

    HWND hWnd = CreateWindowExW(
        0,
        wc.lpszClassName,
        L"微信扫码登录",
        WS_OVERLAPPED | WS_SYSMENU | WS_CAPTION,
        CW_USEDEFAULT, CW_USEDEFAULT,
        360, 420,
        NULL, NULL,
        wc.hInstance,
        NULL
    );
    g_hQrWnd = hWnd;

    RECT rc;
    GetWindowRect(hWnd, &rc);
    int w = rc.right - rc.left;
    int h = rc.bottom - rc.top;
    int sx = GetSystemMetrics(SM_CXSCREEN);
    int sy = GetSystemMetrics(SM_CYSCREEN);
    SetWindowPos(hWnd, NULL,
        (sx - w) / 2, (sy - h) / 2, 0, 0,
        SWP_NOZORDER | SWP_NOSIZE);

    ShowWindow(hWnd, SW_SHOW);
    UpdateWindow(hWnd);

    wchar_t* uuidCopy = (wchar_t*)malloc(sizeof(uuid));
    if (!uuidCopy) {
        if (g_hQrBitmap) { DeleteObject(g_hQrBitmap); g_hQrBitmap = NULL; }
        CoUninitialize();

        return FALSE;
    }
    wcscpy_s(uuidCopy, 64, uuid);

    HANDLE hTh = CreateThread(NULL, 0, WorkerThread, uuidCopy, 0, NULL);
    if (!hTh) {
        free(uuidCopy);
        if (g_hQrBitmap) { DeleteObject(g_hQrBitmap); g_hQrBitmap = NULL; }
        CoUninitialize();

        return FALSE;
    }

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    WaitForSingleObject(hTh, INFINITE);
    CloseHandle(hTh);

    if (g_hQrBitmap) {
        DeleteObject(g_hQrBitmap);
        g_hQrBitmap = NULL;
    }

    CoUninitialize();

    if (!g_szOpenId[0])
    {

        return FALSE;
    }

    wcsncpy_s(result->openId, _countof(result->openId), g_szOpenId, _TRUNCATE);
    wcsncpy_s(result->nick, _countof(result->nick), g_szNick, _TRUNCATE);

    
    return TRUE;
}

// ------------------------------------------------------
// /api/auth/status
// ------------------------------------------------------
BOOL Backend_QueryStatus(const wchar_t* openid, BackendStatus* st)
{
   
    if (!openid || !st) { return FALSE; }

    char openidA[128] = { 0 };
    if (WideToUtf8(openid, openidA, sizeof(openidA)) <= 0)
    {

        return FALSE;
    }

    char inner[256];
    int ilen = std::snprintf(
        inner, sizeof(inner),
        "{\"openId\":\"%s\"}",
        openidA
    );
    if (ilen <= 0 || ilen >= (int)sizeof(inner))
    {

        return FALSE;
    }

    char body[512];
    if (!BuildSecureEnvelopeJson(inner, body, sizeof(body)))
    {

        return FALSE;
    }

    wchar_t url[512];
    wsprintfW(url, L"%s/api/auth/status", g_BackendBase);

    const wchar_t* hdr =
        L"Content-Type: application/json\r\n"
        L"Accept: */*\r\n";

    BYTE* resp = NULL;
    DWORD n = 0;
    if (!HttpRequest(L"POST", url, hdr, body, (DWORD)strlen(body), &resp, &n) || !resp)
    {

        return FALSE;
    }

    const char* json = (const char*)resp;

    ZeroMemory(st, sizeof(BackendStatus));
    ParseJsonBool(json, "isBlacklisted", &st->isBlacklisted);
    ParseJsonBool(json, "hasCard", &st->hasCard);
    ParseJsonBool(json, "cardExpired", &st->cardExpired);
    ParseJsonString(json, "expireText", st->expireText, _countof(st->expireText));
    ParseJsonString(json, "boundCard", st->boundCard, _countof(st->boundCard));

    free(resp);
    
    return TRUE;
}

// ------------------------------------------------------
// /api/auth/bind   （只关心 { success, message } ）
// ------------------------------------------------------
BOOL Backend_BindCard(const wchar_t* openid, const wchar_t* card, BackendStatus* st)
{
   
    if (!openid || !card || !st) { return FALSE; }

    char openidA[128] = { 0 };
    char cardA[128] = { 0 };
    if (WideToUtf8(openid, openidA, sizeof(openidA)) <= 0) { return FALSE; }
    if (WideToUtf8(card, cardA, sizeof(cardA)) <= 0) { return FALSE; }

    // 业务明文：{"openId":"xxx","cardNumber":"yyy"}
    char inner[512];
    int ilen = std::snprintf(
        inner, sizeof(inner),
        "{\"openId\":\"%s\",\"cardNumber\":\"%s\"}",
        openidA, cardA
    );
    if (ilen <= 0 || ilen >= (int)sizeof(inner))
    {

        return FALSE;
    }

    // 加密信封
    char body[1024];
    if (!BuildSecureEnvelopeJson(inner, body, sizeof(body)))
    {

        return FALSE;
    }

    // URL: POST /api/auth/bind
    wchar_t url[512];
    wsprintfW(url, L"%s/api/auth/bind", g_BackendBase);

    const wchar_t* hdr =
        L"Content-Type: application/json\r\n"
        L"Accept: */*\r\n";

    BYTE* resp = NULL;
    DWORD n = 0;
    if (!HttpRequest(L"POST", url, hdr, body, (DWORD)strlen(body), &resp, &n) || !resp)
    {

        return FALSE;
    }

    const char* json = (const char*)resp;

    ZeroMemory(st, sizeof(BackendStatus));

    // 如果以后后端也返回 isBlacklisted，就顺便解析一下
    ParseJsonBool(json, "isBlacklisted", &st->isBlacklisted);

    // 业务成功字段：success
    BOOL succ = FALSE;
    ParseJsonBool(json, "success", &succ);

    // message 填到 expireText 里，用来做提示（比如 “卡号不存在或未激活”）
    ParseJsonString(json, "message", st->expireText, _countof(st->expireText));

    // 这三个字段在绑定接口里其实没啥用，给个合理默认值
    st->hasCard = succ;   // TRUE 表示这次绑定通过
    st->cardExpired = FALSE;  // 不用这个字段
    st->boundCard[0] = 0;      // 这里不返回卡密

    free(resp);
    

    // ★ 关键：直接用 succ 作为函数返回值
    return succ ? TRUE : FALSE;
}

