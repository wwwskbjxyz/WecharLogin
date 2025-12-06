#pragma once
#include <Windows.h>
struct WxLoginResult
{
    wchar_t openId[128];
    wchar_t nick[256];
};

struct BackendStatus
{
    BOOL    isBlacklisted;
    BOOL    hasCard;
    BOOL    cardExpired;
    wchar_t expireText[128];
    wchar_t boundCard[64];   // 后端返回的已绑定卡密
};



// 如果需要，可以在 cpp 里改这个默认后端地址
void WxLogin_SetBackendBase(const wchar_t* baseUrl);

// 1) 弹出二维码窗口，完成微信扫码 + WeGame 登录，拿到 openId + 昵称
//    成功返回 TRUE，结果写到 result 中；失败 FALSE。
BOOL WxLogin_ShowQrAndGetOpenId(WxLoginResult* result);

// 2) 调用后端 /api/auth/status（加密信封版）
//    openId 为微信 openid，status 为输出状态
BOOL Backend_QueryStatus(const wchar_t* openId, BackendStatus* status);

// 3) 调用后端 /api/auth/bind（加密信封版）
//    openId + cardNumber 绑定，status 为绑定后的状态
BOOL Backend_BindCard(const wchar_t* openId, const wchar_t* cardNumber, BackendStatus* status);
#pragma once
