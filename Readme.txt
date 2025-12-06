# 微信扫码登录 + 卡密绑定 Demo

该解决方案包含 **一个服务端 WebAPI** 和 **一个 Windows 客户端示例程序**，演示完整流程：

> 微信扫码 → 获取 OpenId → 调用后端接口查询状态/绑定卡密 → 在客户端窗口中展示卡密
> （**不会做任何驱动或业务登录，仅作演示使用**）

---

## 目录结构说明

* **WecharLogin**
  Windows 客户端示例（Win32 窗口程序），用于：

  * 弹出微信扫码登录界面
  * 调用后端 `/api/auth/status` 查询该微信是否有已绑定卡密
  * 调用后端 `/api/auth/bind` 绑定新卡密
  * 在窗口中打印当前绑定的卡密

* **WechatServers**
  服务端 WebAPI 项目（ASP.NET Core），用于：

  * 生成 / 校验扫码登录使用的临时凭证
  * 提供加密的接口：`/api/auth/status`、`/api/auth/bind` 等
  * 管理卡密、绑定关系、黑名单等业务数据（例如 MySQL / SQLite）

* **WecharLogin.sln**
  VS 解决方案文件，双击即可用 Visual Studio 打开整套项目。

* **Readme.txt**
  当前说明文件。

---

## 一、环境要求

### 服务端（WechatServers）

* .NET SDK 8.0 及以上
* 任意支持 .NET 的操作系统（Windows / Linux / 服务器均可）
* 数据库：Mysql

  * 示例默认支持 MySQL 
* 已准备好的域名或 IP + 端口，例如：
  *  `http://0.0.0.0:8080`

### 客户端（WecharLogin）

* Windows 10 及以上（64 位）
* Visual Studio 2022 及以上（带 C++ 桌面开发组件）
* 可以访问服务端 API 的网络环境

---

## 二、服务端部署步骤（WechatServers）

1. **打开项目**

   * 使用 Visual Studio / Rider / VS Code 打开 `WechatServers` 项目文件夹
   * 或在命令行切到该目录：

     ```bash
     cd WechatServers
     ```

2. **配置应用**

   主要是修改下面两个部分（实际文件名可能略有不同，根据项目中的为准）：

     * 配置数据库连接字符串
     * 示例：

       ```jsonc
       "ConnectionStrings": {
         "Default": "Server=127.0.0.1;Port=3306;Database=sprotect;User=sprotect;Password=你的密码;"
       }
       ```

   * `CryptoCfg` / `WechatAuthOptions`

     * 配置 AES 密钥 / 签名 Secret
     * **这些值要和客户端 `WxLoginClient` 里保持一致**，否则加密请求会验证失败。

3. **初始化数据库**

   * 如果使用 MySQL：

     * 先创建数据库库名（例如 `sprotect`）
     * 再执行项目中提供的建表脚本或自动迁移
   * 如果使用 SQLite：

     * 确保配置的 `.db` 路径存在且可写

4. **启动服务端**

   * Visual Studio：将 `WechatServers` 设为启动项目，按 **F5** 或 **Ctrl+F5**

   * 命令行：

     ```bash
     dotnet run --project WechatServers.csproj
     ```

   * 启动后访问（按实际配置调整）：

     * Swagger 文档：`http://localhost:16500/swagger/index.html`
     * 默认接口示例：

       * `POST /api/auth/status`
       * `POST /api/auth/bind`

   能正常在 swagger 里调用接口后，再去运行客户端。

---

## 三、客户端编译与使用（WecharLogin）

### 1. 编译

1. 双击 `WecharLogin.sln` 用 Visual Studio 打开解决方案。
2. 在解决方案资源管理器中，将 **WecharLogin** 设为启动项目。
3. 根据实际情况检查以下内容：

   * `WxLoginClient.h / .cpp` 中的：

     * 服务端基地址：例如
       // 或
       #define BACKEND_BASE L"http://0.0.0.0:8080"
       ```
     * AES 密钥 / 签名 Secret 与服务器保持一致。
4. 选择生成配置：`Release | x64` 或 `Debug | x64`。
5. 菜单 **“生成” → “生成解决方案”**。

成功后，在类似：

```text
WecharLogin\x64\Release\
```

下可以看到生成的 EXE。

### 2. 使用说明

1. **先启动服务端**（确保 `/api/auth/status`、`/api/auth/bind` 可访问）。

2. 在 Windows 上运行编译后的 `WecharLogin.exe`。

3. 程序会弹出两个窗口：

   * 一个是 **微信扫码登录界面**（显示二维码）
   * 一个是 **主日志窗口**（显示 OpenId / 状态 / 卡密）

4. 流程说明：

   1. 用微信扫描二维码，确认登录。

   2. 客户端调用 `/api/auth/status`：

      * 如果账号是黑名单：

        * 日志窗口提示“已被拉黑”，程序结束。
      * 如果已经绑定有效卡：

        * 日志窗口直接打印卡密（只展示，不做任何登录）。
      * 如果没有卡 / 已过期：

        * 日志窗口提示“当前微信账号没有有效卡密”。

   3. 当需要绑定卡密时：

   

      * 客户端从剪贴板读取卡密，调用 `/api/auth/bind`
      * 成功后：

        * 日志窗口打印绑定成功以及当前卡密 / 到期时间等信息
        * 不做任何驱动或业务登录，仅作为示例展示

---

## 四、自定义与二次开发

* **更换服务端地址**

  * 修改 `WxLoginClient` 中的 `BACKEND_BASE` 宏为你自己的域名或 IP。
* **更换 AES / 签名配置**

  * 同时修改服务器 `CryptoCfg`（或类似配置）和客户端 `WxLoginClient` 中的 key/secret。
* **接入实际业务**

  * 在当前 Demo 中，客户端只负责显示卡密。
  * 实际接入时，可以在“绑定成功 / 发现已有卡密”之后：

    * 把卡密写入本地配置文件
    * 传给已有的驱动登录模块
    * 或调用你自己其他的业务接口

---

## 五、免责声明

本项目为 **学习与演示用途**：

* 仅展示微信扫码登录 + 后端绑定卡密的完整流程
* 客户端不包含任何驱动加载、游戏相关或商业功能
* 请勿用于违反当地法律法规或第三方服务条款的场景

