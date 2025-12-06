// WxLoginDemoWin.cpp
#include <windows.h>
#include <string>
#include <cstdio>
#include "WxLoginClient.h"

#pragma comment(lib, "User32.lib")

// 全局
HWND g_hEdit = nullptr;

// 简单日志输出到多行 Edit
void LogLine(const wchar_t* fmt, ...)
{
    if (!g_hEdit) return;

    wchar_t buffer[1024];
    va_list args;
    va_start(args, fmt);
    _vsnwprintf_s(buffer, _TRUNCATE, fmt, args);
    va_end(args);

    // 在末尾追加
    int len = GetWindowTextLengthW(g_hEdit);
    SendMessageW(g_hEdit, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessageW(g_hEdit, EM_REPLACESEL, FALSE, (LPARAM)buffer);

    // 自动加上换行（如果你不想每次都加，可以在 fmt 里手动带 \n）
    len = GetWindowTextLengthW(g_hEdit);
    if (len > 0) {
        SendMessageW(g_hEdit, EM_SETSEL, (WPARAM)len, (LPARAM)len);
        SendMessageW(g_hEdit, EM_REPLACESEL, FALSE, (LPARAM)L"\r\n");
    }
}

// 从剪贴板读卡密（优先 UNICODE）
bool GetCardFromClipboard(std::string& out)
{
    out.clear();
    if (!OpenClipboard(nullptr))
        return false;

    HANDLE hData = nullptr;

    if (IsClipboardFormatAvailable(CF_UNICODETEXT))
    {
        hData = GetClipboardData(CF_UNICODETEXT);
        if (hData)
        {
            wchar_t* pszTextW = static_cast<wchar_t*>(GlobalLock(hData));
            if (pszTextW)
            {
                int len = WideCharToMultiByte(CP_UTF8, 0, pszTextW, -1, nullptr, 0, nullptr, nullptr);
                if (len > 0)
                {
                    std::string temp(len - 1, '\0');
                    WideCharToMultiByte(CP_UTF8, 0, pszTextW, -1, temp.data(), len, nullptr, nullptr);
                    out = temp;
                }
                GlobalUnlock(hData);
            }
        }
    }
    else if (IsClipboardFormatAvailable(CF_TEXT))
    {
        hData = GetClipboardData(CF_TEXT);
        if (hData)
        {
            char* pszText = static_cast<char*>(GlobalLock(hData));
            if (pszText)
            {
                out = pszText;
                GlobalUnlock(hData);
            }
        }
    }

    CloseClipboard();
    return !out.empty();
}

// 业务逻辑：示例演示，不做任何驱动/登录
void RunDemo(HWND hWnd)
{
    LogLine(L"[*] 微信扫码登录示例启动...");

    // 1. 微信扫码登录
    WxLoginResult wx = {};
    if (!WxLogin_ShowQrAndGetOpenId(&wx))
    {
        LogLine(L"[!] 微信登录失败，无法获取 openid");
        MessageBoxW(hWnd, L"微信登录失败，无法获取 openId。", L"错误", MB_ICONERROR);
        return;
    }

    LogLine(L"[+] 微信登录成功！");
    LogLine(L"    OpenId = %s", wx.openId);

    // 2. 查询后端状态
    BackendStatus st = {};
    if (!Backend_QueryStatus(wx.openId, &st))
    {
        LogLine(L"[!] 查询后端失败 (/api/auth/status)");
        MessageBoxW(hWnd, L"查询后端失败。", L"错误", MB_ICONERROR);
        return;
    }

    LogLine(L"");
    LogLine(L"[后端状态]");
    LogLine(L"    isBlacklisted : %s", st.isBlacklisted ? L"true" : L"false");
    LogLine(L"    hasCard       : %s", st.hasCard ? L"true" : L"false");
    LogLine(L"    cardExpired   : %s", st.cardExpired ? L"true" : L"false");
    if (st.expireText[0])
        LogLine(L"    expireText    : %s", st.expireText);
    if (st.boundCard[0])
        LogLine(L"    boundCard     : %s", st.boundCard);

    if (st.isBlacklisted)
    {
        LogLine(L"");
        LogLine(L"[!] 该微信账号已被拉黑，示例程序结束。");
        MessageBoxW(hWnd, L"该微信账号已被拉黑。", L"提示", MB_ICONWARNING);
        return;
    }

    // 3. 如果已绑定且未过期 -> 打印卡密
    if (st.hasCard && !st.cardExpired && st.boundCard[0])
    {
        char cardA[64] = { 0 };
        WideCharToMultiByte(CP_UTF8, 0, st.boundCard, -1, cardA, sizeof(cardA), nullptr, nullptr);

        LogLine(L"");
        LogLine(L"[INFO] 当前微信已绑定有效卡密：");
        LogLine(L"       %S", cardA);
        LogLine(L"[INFO] 本示例只打印卡密，不做任何登录业务。");

        MessageBoxW(hWnd, L"已检测到有效绑定卡密，已在窗口中显示。", L"完成", MB_OK | MB_ICONINFORMATION);
        return;
    }

    // 4. 没有卡 -> 提示绑定流程（通过剪贴板）
    LogLine(L"");
    LogLine(L"[INFO] 当前微信账号没有有效卡密（未绑定或已过期）。");
    LogLine(L"[INFO] 下面演示绑定流程：请将 32 位卡密复制到剪贴板。");

    while (true)
    {
        int mb = MessageBoxW(
            hWnd,
            L"请先复制要绑定的 32 位卡密到剪贴板，然后点击“确定”继续。\n\n"
            L"点击“取消”可结束示例。",
            L"绑定卡密",
            MB_OKCANCEL | MB_ICONQUESTION
        );

        if (mb == IDCANCEL)
        {
            LogLine(L"[INFO] 用户取消绑定流程，示例结束。");
            return;
        }

        std::string cardInput;
        if (!GetCardFromClipboard(cardInput))
        {
            LogLine(L"[WARN] 未能从剪贴板读取卡密，请确认已复制文本。");
            continue;
        }

        // 去掉两端空白
        while (!cardInput.empty() && (cardInput.back() == '\r' || cardInput.back() == '\n' || cardInput.back() == ' '))
            cardInput.pop_back();

        if (cardInput.size() != 32)
        {
            LogLine(L"[WARN] 读到的卡密长度为 %d，必须为 32 位，请重新复制。", (int)cardInput.size());
            continue;
        }

        LogLine(L"[INFO] 从剪贴板读取到卡密：%S", cardInput.c_str());

        // char -> wchar_t
        wchar_t cardW[128] = { 0 };
        MultiByteToWideChar(CP_UTF8, 0, cardInput.c_str(), -1, cardW, _countof(cardW));

        BackendStatus stBind = {};
        if (!Backend_BindCard(wx.openId, cardW, &stBind))
        {
            if (stBind.expireText[0])
                LogLine(L"[WARN] 绑定失败: %s", stBind.expireText);
            else
                LogLine(L"[WARN] 绑定失败，可能是网络错误或卡密无效。");

            LogLine(L"");
            continue;
        }

        if (stBind.isBlacklisted)
        {
            LogLine(L"[!] 绑定返回黑名单状态，示例结束。");
            MessageBoxW(hWnd, L"账号已被拉黑。", L"提示", MB_ICONWARNING);
            return;
        }

        char finalCard[64] = { 0 };
        if (stBind.boundCard[0])
        {
            WideCharToMultiByte(CP_UTF8, 0, stBind.boundCard, -1, finalCard, sizeof(finalCard), nullptr, nullptr);
        }
        else
        {
            strncpy_s(finalCard, sizeof(finalCard), cardInput.c_str(), _TRUNCATE);
        }

        LogLine(L"");
        LogLine(L"[OK] 绑定成功！");
        LogLine(L"     当前绑定的卡密为: %S", finalCard);
        if (stBind.expireText[0])
            LogLine(L"     到期时间: %s", stBind.expireText);

        LogLine(L"");
        LogLine(L"[INFO] 示例程序到此结束，不会把卡密传给任何驱动/业务，仅作演示用。");

        MessageBoxW(hWnd, L"绑定成功，卡密已在窗口中显示。", L"完成", MB_OK | MB_ICONINFORMATION);
        break;
    }
}

// 窗口过程
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_CREATE:
    {
        // 创建一个多行、只读 Edit 作为日志窗口
        g_hEdit = CreateWindowExW(
            WS_EX_CLIENTEDGE,
            L"EDIT",
            nullptr,
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL |
            ES_READONLY | WS_VSCROLL,
            10, 10, 600, 360,
            hWnd,
            (HMENU)1001,
            GetModuleHandleW(nullptr),
            nullptr
        );

        LogLine(L"微信扫码登录 + 卡密绑定 示例窗口");
        LogLine(L"--------------------------------------");
        LogLine(L"点击菜单 / 或稍等几秒自动开始演示...");
        // 直接在创建后启动演示
        RunDemo(hWnd);
        return 0;
    }
    case WM_SIZE:
    {
        if (g_hEdit)
        {
            RECT rc;
            GetClientRect(hWnd, &rc);
            MoveWindow(g_hEdit, 10, 10, rc.right - 20, rc.bottom - 20, TRUE);
        }
        return 0;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        break;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// WinMain 入口（窗口程序，无控制台）
int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow)
{
    const wchar_t CLASS_NAME[] = L"WxLoginDemoWinClass";

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = CLASS_NAME;

    if (!RegisterClassExW(&wc))
        return 0;

    HWND hWnd = CreateWindowExW(
        0,
        CLASS_NAME,
        L"微信扫码登录 + 卡密绑定 示例",
        WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_SIZEBOX, // 简单点，不允许缩放/最大化
        CW_USEDEFAULT, CW_USEDEFAULT,
        640, 440,
        nullptr,
        nullptr,
        hInstance,
        nullptr
    );

    if (!hWnd)
        return 0;

    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    // 消息循环
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return (int)msg.wParam;
}
