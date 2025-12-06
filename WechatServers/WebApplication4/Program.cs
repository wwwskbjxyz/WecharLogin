using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Encodings.Web;
using Microsoft.Data.Sqlite;
using MySqlConnector;
using SQLitePCL;


//本服务端鉴于验证数据库查询，如使用不同验证请自行查询SQLite数据库语句自行修改
public static class Program
{
    // ===================== 全局配置 =====================

    // MySQL 连接字符串
    private const string MySqlConnStr =
        "Server=127.0.0.1;Port=3306;Database=test;User ID=test;Password=test;TreatTinyAsBoolean=true;";

    // licenses 表里“卡密”字段名，比如 key / card / license_key
    private const string LicenseCardColumn = "license";

    private static readonly string SqlitePath =
        Path.Combine(AppContext.BaseDirectory, "idc.db");

    private static readonly string SqliteConnStr =
        new SqliteConnectionStringBuilder
        {
            DataSource = SqlitePath,
            Mode = SqliteOpenMode.ReadWrite
        }.ToString();

    // AES / HMAC，必须和客户端那边一致请自行修改
    private static readonly byte[] AesKey =
    {
        0x10,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
        0x01,0x12,0x23,0x34,0x45,0x56,0x67,0x78,
        0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,
        0x13,0x57,0x9B,0xDF,0x24,0x68,0xAC,0xF0
    };

    // HMAC 签名密钥必须和客户端那边一致
    private const string SigSecret = "32位随机密钥";

    private static bool _mysqlSchemaReady = false;

  
    private static readonly JsonSerializerOptions LogJsonOptions = new JsonSerializerOptions
    {
        WriteIndented = false,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };
    private static readonly JsonSerializerOptions PayloadJsonOptions = new JsonSerializerOptions
    {
        PropertyNameCaseInsensitive = true
    };

    // ===================== Main =====================

    public static async Task Main(string[] args)
    {
        // 初始化 SQLitePCL（bundle_e_sqlite3）
        Batteries.Init();

        if (!File.Exists(SqlitePath))
        {
            Console.WriteLine($"[WARN] 找不到 SQLite 数据库: {SqlitePath}");
        }

        var builder = WebApplication.CreateBuilder(args);
        builder.Services.AddSingleton<SessionStore>();

        // 监听 8080 端口（所有 IP）
        builder.WebHost.UseUrls("http://0.0.0.0:8080");

        var app = builder.Build();

        await EnsureMySqlSchemaAsync();

        // 静态文件中间件
        app.UseDefaultFiles();   // 支持自动找 index.html
        app.UseStaticFiles();

        app.MapGet("/", () => "OpenIdMiniServer is running");

        // ------------ 管理员登录 ------------
        app.MapPost("/api/auth/login", LoginHandler);
        app.MapPost("/api/auth/getUserInfo", GetUserInfoHandler);

        // ------------ 管理端：查卡 ------------
        app.MapGet("/api/admin/cards/{cardNumber}", AdminCardHandler);

        // ------------ 管理端：封禁 / 解封 OpenId ------------
        app.MapPost("/api/admin/ban", AdminBanHandler);
        app.MapPost("/api/admin/unban", AdminUnbanHandler);

        // ------------ 管理端：OpenId 列表 + 绑定历史 ------------
        app.MapGet("/api/admin/openids", AdminOpenIdsHandler);
        app.MapGet("/api/admin/openids/{openid}/bindings", AdminBindingsHandler);

        // ------------ C++ 端：加密接口 ------------
        app.MapPost("/api/auth/status", AuthStatusHandler);
        app.MapPost("/api/auth/bind", AuthBindHandler);

        Console.WriteLine("[INFO] OpenIdMiniServer listening on http://0.0.0.0:8080");
        await app.RunAsync();
    }

    // ===================== 通用日志封装 =====================

    private static IResult JsonWithLog(string api, object value, int? statusCode = null)
    {
        var json = JsonSerializer.Serialize(value, LogJsonOptions);
        Console.WriteLine($"[API {api}] Response: {json}");
        return statusCode.HasValue
            ? Results.Json(value, statusCode: statusCode.Value)
            : Results.Json(value);
    }

    private static IResult BadRequestWithLog(string api, object value)
    {
        var json = JsonSerializer.Serialize(value, LogJsonOptions);
        Console.WriteLine($"[API {api}] 400 Response: {json}");
        return Results.BadRequest(value);
    }

    // ===================== Endpoints 实现 =====================

    // ----- /api/auth/login -----
    private static async Task<IResult> LoginHandler(LoginRequest req, SessionStore sessions)
    {
        Console.WriteLine("[API /api/auth/login] Request: " +
                          JsonSerializer.Serialize(req, LogJsonOptions));

        await using var conn = new SqliteConnection(SqliteConnStr);
        await conn.OpenAsync();

        var cmd = conn.CreateCommand();
        cmd.CommandText = @"SELECT id, username, password, banned 
                            FROM admins WHERE id = 1 LIMIT 1;";
        await using var reader = await cmd.ExecuteReaderAsync();

        if (!await reader.ReadAsync())
        {
            var resp = new ApiResponse<object>
            {
                Code = 1,
                Message = "admin 账号不存在"
            };
            return JsonWithLog("/api/auth/login", resp);
        }

        var banned = reader.GetInt32(3);
        if (banned != 0)
        {
            var resp = new ApiResponse<object>
            {
                Code = 1,
                Message = "admin 已被禁用"
            };
            return JsonWithLog("/api/auth/login", resp);
        }

        var username = reader.GetString(1);
        var password = reader.GetString(2);

        if (!string.Equals(username, req.Username, StringComparison.Ordinal) ||
            !string.Equals(password, req.Password, StringComparison.Ordinal))
        {
            var resp = new ApiResponse<object>
            {
                Code = 1,
                Message = "用户名或密码错误"
            };
            return JsonWithLog("/api/auth/login", resp);
        }

        var token = Guid.NewGuid().ToString("N");
        sessions.Set(token, new AdminSession { Username = username, IsSuper = true });

        var okResp = new ApiResponse<LoginResult>
        {
            Code = 0,
            Message = "ok",
            Data = new LoginResult
            {
                Username = username,
                Token = token,
                IsSuper = true
            }
        };
        return JsonWithLog("/api/auth/login", okResp);
    }

    // ----- /api/auth/getUserInfo -----
    private static IResult GetUserInfoHandler(HttpContext ctx, SessionStore sessions)
    {
        Console.WriteLine("[API /api/auth/getUserInfo] Request");

        var session = GetAdminSession(ctx, sessions);
        if (session is null)
        {
            var resp = new ApiResponse<object>
            {
                Code = 401,
                Message = "未登录"
            };
            return JsonWithLog("/api/auth/getUserInfo", resp, 401);
        }

        var okResp = new ApiResponse<UserInfoResult>
        {
            Code = 0,
            Message = "ok",
            Data = new UserInfoResult
            {
                Username = session.Username,
                IsSuper = session.IsSuper
            }
        };
        return JsonWithLog("/api/auth/getUserInfo", okResp);
    }

    // ----- /api/admin/cards/{cardNumber} -----
    private static async Task<IResult> AdminCardHandler(HttpContext ctx, string cardNumber, SessionStore sessions)
    {
        Console.WriteLine($"[API /api/admin/cards/{cardNumber}] Request");

        if (GetAdminSession(ctx, sessions) is null)
            return Results.StatusCode(401);

        var cardInfo = await LoadLicenseAsync(cardNumber);
        if (cardInfo is null)
        {
            var resp = new
            {
                exists = false,
                status = "not_found"
            };
            return JsonWithLog($"/api/admin/cards/{cardNumber}", resp);
        }

        string status;
        bool expired = false;
        DateTime? expireTime = null;

        if (cardInfo.Banned == 1)
        {
            status = "banned";
        }
        else if (cardInfo.ActivatedAt == 0 && cardInfo.ExpiresAt == 0)
        {
            status = "normal_not_activated";
        }
        else if (cardInfo.ExpiresAt > 0)
        {
            expireTime = UnixToUtc(cardInfo.ExpiresAt);
            expired = expireTime <= DateTime.UtcNow;
            status = expired ? "expired" : "active";
        }
        else
        {
            status = "active";
        }

        var ok = new
        {
            exists = true,
            status,
            banned = cardInfo.Banned == 1,
            activatedAt = cardInfo.ActivatedAt == 0 ? (DateTime?)null : UnixToUtc(cardInfo.ActivatedAt),
            expiresAt = cardInfo.ExpiresAt == 0 ? (DateTime?)null : expireTime,
            expireText = expireTime?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
        };
        return JsonWithLog($"/api/admin/cards/{cardNumber}", ok);
    }

    // ----- /api/admin/ban -----
    private static async Task<IResult> AdminBanHandler(HttpContext ctx, BanRequest req, SessionStore sessions)
    {
        Console.WriteLine("[API /api/admin/ban] Request: " +
                          JsonSerializer.Serialize(req, LogJsonOptions));

        if (GetAdminSession(ctx, sessions) is null)
            return Results.StatusCode(401);

        await using var conn = new MySqlConnection(MySqlConnStr);
        await conn.OpenAsync();

        var cmd = conn.CreateCommand();
        cmd.CommandText = @"
INSERT INTO openid_blacklist(openid, created_at_utc)
VALUES(@openid, UNIX_TIMESTAMP())
ON DUPLICATE KEY UPDATE created_at_utc = UNIX_TIMESTAMP();";
        cmd.Parameters.AddWithValue("@openid", req.OpenId);
        await cmd.ExecuteNonQueryAsync();

        cmd = conn.CreateCommand();
        cmd.CommandText = @"UPDATE openid_scan_logs SET is_blacklisted = 1 WHERE openid = @openid;";
        cmd.Parameters.AddWithValue("@openid", req.OpenId);
        await cmd.ExecuteNonQueryAsync();

        var resp = new { success = true };
        return JsonWithLog("/api/admin/ban", resp);
    }

    // ----- /api/admin/unban -----
    private static async Task<IResult> AdminUnbanHandler(HttpContext ctx, BanRequest req, SessionStore sessions)
    {
        Console.WriteLine("[API /api/admin/unban] Request: " +
                          JsonSerializer.Serialize(req, LogJsonOptions));

        if (GetAdminSession(ctx, sessions) is null)
            return Results.StatusCode(401);

        await using var conn = new MySqlConnection(MySqlConnStr);
        await conn.OpenAsync();

        var cmd = conn.CreateCommand();
        cmd.CommandText = @"DELETE FROM openid_blacklist WHERE openid = @openid;";
        cmd.Parameters.AddWithValue("@openid", req.OpenId);
        await cmd.ExecuteNonQueryAsync();

        cmd = conn.CreateCommand();
        cmd.CommandText = @"UPDATE openid_scan_logs SET is_blacklisted = 0 WHERE openid = @openid;";
        cmd.Parameters.AddWithValue("@openid", req.OpenId);
        await cmd.ExecuteNonQueryAsync();

        var resp = new { success = true };
        return JsonWithLog("/api/admin/unban", resp);
    }

    // ----- /api/admin/openids -----
    private static async Task<IResult> AdminOpenIdsHandler(HttpContext ctx, string? search, SessionStore sessions)
    {
        if (GetAdminSession(ctx, sessions) is null)
            return Results.StatusCode(401);

        await using var conn = new MySqlConnection(MySqlConnStr);
        await conn.OpenAsync();

        var sql = @"
SELECT 
    o.openid,
    CASE WHEN b.openid IS NULL THEN 0 ELSE 1 END AS is_blacklisted,
    (SELECT c2.card_number 
     FROM openid_cards c2 
     WHERE c2.openid = o.openid 
     ORDER BY c2.expire_time_utc DESC, c2.created_at_utc DESC 
     LIMIT 1) AS current_card,
    (SELECT c2.expire_time_utc 
     FROM openid_cards c2 
     WHERE c2.openid = o.openid 
     ORDER BY c2.expire_time_utc DESC, c2.created_at_utc DESC 
     LIMIT 1) AS current_expire,
    s.first_seen_utc,
    s.last_seen_utc,
    s.scan_count,
    s.last_ip
FROM (
    SELECT openid FROM openid_blacklist
    UNION
    SELECT openid FROM openid_cards
    UNION
    SELECT openid FROM openid_scan_logs       -- ★ 把扫码日志里的 openid 也加进来
) o
LEFT JOIN openid_blacklist b ON b.openid = o.openid
LEFT JOIN openid_scan_logs s ON s.openid = o.openid
";

        if (!string.IsNullOrWhiteSpace(search))
        {
            sql += " WHERE o.openid LIKE @kw ";
        }

        sql += " ORDER BY o.openid;";

        var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        if (!string.IsNullOrWhiteSpace(search))
            cmd.Parameters.AddWithValue("@kw", "%" + search + "%");

        var list = new List<OpenIdSummary>();

        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            var openid = reader.GetString(0);
            var isBlacklisted = reader.GetInt32(1) != 0;
            string? card = reader.IsDBNull(2) ? null : reader.GetString(2);
            long currentExpireUnix = reader.IsDBNull(3) ? 0 : reader.GetInt64(3);

            long firstSeenUnix = reader.IsDBNull(4) ? 0 : reader.GetInt64(4);
            long lastSeenUnix = reader.IsDBNull(5) ? 0 : reader.GetInt64(5);
            int scanCount = reader.IsDBNull(6) ? 0 : reader.GetInt32(6);
            string? lastIp = reader.IsDBNull(7) ? null : reader.GetString(7);

            DateTime? currentExpire = null;
            if (currentExpireUnix > 0)
                currentExpire = UnixToUtc(currentExpireUnix).ToLocalTime();

            DateTime? firstSeen = null;
            if (firstSeenUnix > 0)
                firstSeen = UnixToUtc(firstSeenUnix).ToLocalTime();

            DateTime? lastSeen = null;
            if (lastSeenUnix > 0)
                lastSeen = UnixToUtc(lastSeenUnix).ToLocalTime();

            list.Add(new OpenIdSummary
            {
                OpenId = openid,
                IsBlacklisted = isBlacklisted,
                CurrentCard = card,
                CurrentExpire = currentExpire,
                FirstSeen = firstSeen,
                LastSeen = lastSeen,
                ScanCount = scanCount,
                LastIp = lastIp
            });
        }

        return Results.Json(list);
    }


    // ----- /api/admin/openids/{openid}/bindings -----
    private static async Task<IResult> AdminBindingsHandler(HttpContext ctx, string openid, SessionStore sessions)
    {
        Console.WriteLine($"[API /api/admin/openids/{openid}/bindings] Request");

        if (GetAdminSession(ctx, sessions) is null)
            return Results.StatusCode(401);

        await using var conn = new MySqlConnection(MySqlConnStr);
        await conn.OpenAsync();

        var cmd = conn.CreateCommand();
        cmd.CommandText = @"
SELECT card_number, expire_time_utc, created_at_utc
FROM openid_cards
WHERE openid = @openid
ORDER BY created_at_utc DESC;";
        cmd.Parameters.AddWithValue("@openid", openid);

        var list = new List<OpenIdBindingHistory>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            var card = reader.GetString(0);
            var expUnix = reader.GetInt64(1);
            var createdUnix = reader.GetInt64(2);

            list.Add(new OpenIdBindingHistory
            {
                CardNumber = card,
                ExpireTime = UnixToUtc(expUnix).ToLocalTime(),
                CreatedAt = UnixToUtc(createdUnix).ToLocalTime()
            });
        }

        return JsonWithLog($"/api/admin/openids/{openid}/bindings", list);
    }

    // ----- /api/auth/status -----
    private static async Task<IResult> AuthStatusHandler(HttpContext ctx, SecureEnvelope env)
    {
        Console.WriteLine("[API /api/auth/status] Envelope: " +
                          JsonSerializer.Serialize(env, LogJsonOptions));

        if (!TryDecryptEnvelope<StatusPayload>(env, AesKey, SigSecret, out var payload, out var err))
        {
            var resp = new { success = false, message = err ?? "invalid envelope" };
            return BadRequestWithLog("/api/auth/status", resp);
        }

        Console.WriteLine("[API /api/auth/status] Decrypted payload: " +
                          JsonSerializer.Serialize(payload, LogJsonOptions));

        var openId = (payload!.OpenId ?? string.Empty).Trim();

        var status = await GetOpenIdStatusAsync(openId, ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown");
        return JsonWithLog("/api/auth/status", status);
    }

    // ----- /api/auth/bind -----
    // 绑定卡密（加密接口）
    private static async Task<IResult> AuthBindHandler(SecureEnvelope env)
    {
        Console.WriteLine("[API /api/auth/bind] Envelope: " +
                          JsonSerializer.Serialize(env, LogJsonOptions));

        if (!TryDecryptEnvelope<BindPayload>(env, AesKey, SigSecret, out var payload, out var err))
        {
            var resp = new { success = false, message = err ?? "invalid envelope" };
            return BadRequestWithLog("/api/auth/bind", resp);
        }

        Console.WriteLine("[API /api/auth/bind] Decrypted payload: " +
                          JsonSerializer.Serialize(payload, LogJsonOptions));

        var openId = (payload!.OpenId ?? string.Empty).Trim();
        var cardNumber = (payload.CardNumber ?? string.Empty).Trim();

        var cardInfo = await LoadLicenseAsync(cardNumber);
        if (cardInfo is null || cardInfo.Banned == 1)
        {
            var resp = new { success = false, message = "卡号不存在或未激活" };
            return JsonWithLog("/api/auth/bind", resp);
        }

        var nowUtc = DateTime.UtcNow;
        long expUnix = 0;   // 最终写入 MySQL openid_cards.expire_time_utc 的值

        // 如果 licenses 里已经有 expires_at，就严格按 licenses 的来
        if (cardInfo.ExpiresAt > 0)
        {
            expUnix = cardInfo.ExpiresAt;
            var expireUtc = UnixToUtc(expUnix);

            if (expireUtc <= nowUtc)
            {
                var resp = new { success = false, message = "卡号已过期" };
                return JsonWithLog("/api/auth/bind", resp);
            }
        }
        else
        {
            // 新卡：activated_at=0、expires_at=0
            // 暂时先写 0，等 licenses 更新后，由 /api/auth/status 里的同步逻辑修正
            expUnix = 0;
        }

        // 写入 / 更新 openid_cards
        await using (var conn = new MySqlConnection(MySqlConnStr))
        {
            await conn.OpenAsync();

            var cmd = conn.CreateCommand();
            cmd.CommandText = @"
INSERT INTO openid_cards(openid, card_number, expire_time_utc, created_at_utc)
VALUES(@openid, @card, @exp, UNIX_TIMESTAMP())
ON DUPLICATE KEY UPDATE
    card_number     = VALUES(card_number),
    expire_time_utc = VALUES(expire_time_utc),
    created_at_utc  = UNIX_TIMESTAMP();";

            cmd.Parameters.AddWithValue("@openid", openId);
            cmd.Parameters.AddWithValue("@card", cardNumber);
            cmd.Parameters.AddWithValue("@exp", expUnix);
            await cmd.ExecuteNonQueryAsync();
        }

        // 再查一遍状态
        var status = await GetOpenIdStatusAsync(openId, null);
        if (!status.HasCard)
        {
            var failResp = new { success = false, message = "绑定失败" };
            return JsonWithLog("/api/auth/bind", failResp);
        }

        var okResp = new
        {
            success = true,
            expireText = status.ExpireText
        };
        return JsonWithLog("/api/auth/bind", okResp);
    }


    // ===================== Helper 方法 =====================

    private static AdminSession? GetAdminSession(HttpContext ctx, SessionStore sessions)
    {
        var auth = ctx.Request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(auth)) return null;
        const string prefix = "Bearer ";
        if (!auth.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return null;
        var token = auth[prefix.Length..].Trim();
        return sessions.Get(token);
    }

    private static DateTime UnixToUtc(long unix) =>
        DateTimeOffset.FromUnixTimeSeconds(unix).UtcDateTime;

    private static long ToUnix(DateTime dt) =>
        new DateTimeOffset(dt.ToUniversalTime()).ToUnixTimeSeconds();

    private static async Task<LicenseRow?> LoadLicenseAsync(string cardNumber)
    {
        if (!File.Exists(SqlitePath)) return null;

        await using var conn = new SqliteConnection(SqliteConnStr);
        await conn.OpenAsync();

        var cmd = conn.CreateCommand();
        cmd.CommandText = $@"
SELECT {LicenseCardColumn} AS CardNumber,
       activated_at AS ActivatedAt,
       expires_at   AS ExpiresAt,
       banned       AS Banned
FROM licenses
WHERE {LicenseCardColumn} = @card
LIMIT 1;";
        cmd.Parameters.AddWithValue("@card", cardNumber);

        await using var reader = await cmd.ExecuteReaderAsync();
        if (!await reader.ReadAsync()) return null;

        return new LicenseRow
        {
            CardNumber = reader.GetString(0),
            ActivatedAt = reader.GetInt64(1),
            ExpiresAt = reader.GetInt64(2),
            Banned = reader.GetInt32(3)
        };
    }

    private static async Task<BackendStatusResponse> GetOpenIdStatusAsync(string openId, string? ip)
    {
        await using var conn = new MySqlConnection(MySqlConnStr);
        await conn.OpenAsync();

        // 1. 先看黑名单
        var cmd = conn.CreateCommand();
        cmd.CommandText = @"SELECT 1 FROM openid_blacklist WHERE openid = @openid LIMIT 1;";
        cmd.Parameters.AddWithValue("@openid", openId);
        var blk = await cmd.ExecuteScalarAsync() != null;

        // 2. 查这个 openid 当前绑定的卡（只要卡号，不信任 expire_time_utc）
        cmd = conn.CreateCommand();
        cmd.CommandText = @"
SELECT card_number, expire_time_utc
FROM openid_cards
WHERE openid = @openid
ORDER BY expire_time_utc DESC, created_at_utc DESC
LIMIT 1;";
        cmd.Parameters.AddWithValue("@openid", openId);

        string? card = null;
        long expUnixFromMySql = 0;

        await using (var reader = await cmd.ExecuteReaderAsync())
        {
            if (await reader.ReadAsync())
            {
                card = reader.GetString(0);
                expUnixFromMySql = reader.GetInt64(1); // 仅做对比用，不作为真相
            }
        }

        var nowUtc = DateTime.UtcNow;
        bool hasCard = false;
        bool cardExpired = false;
        string expireText = string.Empty;

        // 3. 如果有绑定卡号，每次都去 SQLite licenses 同步最新过期时间
        if (!string.IsNullOrWhiteSpace(card))
        {
            var lic = await LoadLicenseAsync(card);

            long expUnixFromSqlite = 0;
            bool bannedByLicense = false;

            if (lic != null)
            {
                expUnixFromSqlite = lic.ExpiresAt;
                bannedByLicense = lic.Banned == 1;
            }

            // 3.1. 以 SQLite 为准：无论 0 还是非 0，都写回 MySQL
            var newExpUnix = expUnixFromSqlite; // 可能是 0

            var upd = conn.CreateCommand();
            upd.CommandText = @"UPDATE openid_cards 
                            SET expire_time_utc = @exp 
                            WHERE openid = @openid;";
            upd.Parameters.AddWithValue("@exp", newExpUnix);
            upd.Parameters.AddWithValue("@openid", openId);
            await upd.ExecuteNonQueryAsync();

            // 3.2. 根据 SQLite 的数据计算 hasCard / 过期
            // 规则：只要卡存在并且 license 没被封，就算 HasCard=true
            hasCard = (lic != null) && !bannedByLicense;

            if (hasCard && newExpUnix > 0)
            {
                var dt = UnixToUtc(newExpUnix);
                cardExpired = dt <= nowUtc;
                expireText = dt.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
            }
            else
            {
                // expires_at = 0 => 没设置到期时间，不算过期，ExpireText 为空字符串
                cardExpired = false;
                expireText = string.Empty;
            }
        }

        // 4. 写扫码日志：每次 /status 都会记一次，顺便带上 IP
        if (!string.IsNullOrWhiteSpace(openId))
        {
            cmd = conn.CreateCommand();
            cmd.CommandText = @"
INSERT INTO openid_scan_logs(openid, first_seen_utc, last_seen_utc, scan_count, last_ip)
VALUES(@openid, UNIX_TIMESTAMP(), UNIX_TIMESTAMP(), 1, @ip)
ON DUPLICATE KEY UPDATE
    last_seen_utc = UNIX_TIMESTAMP(),
    scan_count    = scan_count + 1,
    last_ip       = @ip;";
            cmd.Parameters.AddWithValue("@openid", openId);
            cmd.Parameters.AddWithValue("@ip", ip ?? (object)DBNull.Value);
            await cmd.ExecuteNonQueryAsync();
        }

        var status = new BackendStatusResponse
        {
            IsBlacklisted = blk,
            HasCard = hasCard,
            CardExpired = cardExpired,
            ExpireText = expireText,
            BoundCard = card ?? string.Empty
        };

        Console.WriteLine("[GetOpenIdStatusAsync] Result: " +
                          JsonSerializer.Serialize(status, LogJsonOptions));

        return status;
    }


    private static async Task EnsureMySqlSchemaAsync()
    {
        if (_mysqlSchemaReady) return;

        await using var conn = new MySqlConnection(MySqlConnStr);
        await conn.OpenAsync();

        var cmd = conn.CreateCommand();
        cmd.CommandText = @"
CREATE TABLE IF NOT EXISTS openid_blacklist(
    openid VARCHAR(128) PRIMARY KEY,
    created_at_utc BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS openid_cards(
    id INT AUTO_INCREMENT PRIMARY KEY,
    openid VARCHAR(128) NOT NULL,
    card_number VARCHAR(200) NOT NULL,
    expire_time_utc BIGINT NOT NULL,
    created_at_utc BIGINT NOT NULL,
    UNIQUE KEY uq_openid(openid)
);

CREATE TABLE IF NOT EXISTS openid_scan_logs(
    openid VARCHAR(128) PRIMARY KEY,
    first_seen_utc BIGINT NOT NULL,
    last_seen_utc  BIGINT NOT NULL,
    scan_count INT NOT NULL,
    last_ip VARCHAR(64),
    is_blacklisted TINYINT(1) NOT NULL DEFAULT 0
);";
        await cmd.ExecuteNonQueryAsync();

        _mysqlSchemaReady = true;
        Console.WriteLine("[EnsureMySqlSchema] MySQL tables ready");
    }

    // AES + HMAC 解密
    private static bool TryDecryptEnvelope<T>(
        SecureEnvelope env,
        byte[] aesKey,
        string sigSecret,
        out T? payload,
        out string? error)
    {
        payload = default;
        error = null;

        byte[] ivBytes;
        byte[] cipherBytes;

        try
        {
            ivBytes = Convert.FromBase64String(env.Iv);
            cipherBytes = Convert.FromBase64String(env.Payload);
        }
        catch
        {
            error = "Base64 解码失败";
            return false;
        }

        var raw = $"{env.Iv}|{env.Payload}|{env.Ts}";
        var keyBytes = Encoding.UTF8.GetBytes(sigSecret);

        using var hmac = new HMACSHA256(keyBytes);
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(raw));
        var sigHex = BitConverter.ToString(hash).Replace("-", "");

        if (!sigHex.Equals(env.Sig, StringComparison.OrdinalIgnoreCase))
        {
            error = "签名校验失败";
            return false;
        }

        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (Math.Abs(now - env.Ts) > 300)
        {
            
            Console.WriteLine($"[TryDecryptEnvelope] 警告：请求时间戳偏差较大，now={now}, ts={env.Ts}");
        }

        using var aes = Aes.Create();
        aes.Key = aesKey;
        aes.IV = ivBytes;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        try
        {
            using var ms = new MemoryStream();
            using (var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
            {
                cs.Write(cipherBytes, 0, cipherBytes.Length);
                cs.FlushFinalBlock();
            }

            var jsonPlain = Encoding.UTF8.GetString(ms.ToArray());
            Console.WriteLine("[TryDecryptEnvelope] Decrypted JSON: " + jsonPlain);

           
            payload = JsonSerializer.Deserialize<T>(jsonPlain, PayloadJsonOptions);
            if (payload == null)
            {
                error = "payload 为空";
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine("[TryDecryptEnvelope] AES 解密异常: " + ex);
            error = "AES 解密失败";
            return false;
        }
    }
}



public record LoginRequest(string Username, string Password);

public class ApiResponse<T>
{
    public int Code { get; set; }
    public string Message { get; set; } = string.Empty;
    public T? Data { get; set; }
}

public class LoginResult
{
    public string Username { get; set; } = string.Empty;
    public string Token { get; set; } = string.Empty;
    public bool IsSuper { get; set; }
}

public class UserInfoResult
{
    public string Username { get; set; } = string.Empty;
    public bool IsSuper { get; set; }
}

public class AdminSession
{
    public string Username { get; set; } = string.Empty;
    public bool IsSuper { get; set; }
}

public class SessionStore
{
    private readonly Dictionary<string, AdminSession> _sessions = new();

    public void Set(string token, AdminSession session)
    {
        lock (_sessions) _sessions[token] = session;
    }

    public AdminSession? Get(string token)
    {
        lock (_sessions)
        {
            _sessions.TryGetValue(token, out var s);
            return s;
        }
    }
}

public class LicenseRow
{
    public string CardNumber { get; set; } = string.Empty;
    public long ActivatedAt { get; set; }
    public long ExpiresAt { get; set; }
    public int Banned { get; set; }
}

public record BanRequest(string OpenId);

public class OpenIdSummary
{
    public string OpenId { get; set; } = string.Empty;
    public bool IsBlacklisted { get; set; }
    public string? CurrentCard { get; set; }
    public DateTime? CurrentExpire { get; set; }
   
    public DateTime? FirstSeen { get; set; }
    public DateTime? LastSeen { get; set; }
    public int ScanCount { get; set; }
    public string? LastIp { get; set; }
}

public class OpenIdBindingHistory
{
    public string CardNumber { get; set; } = string.Empty;
    public DateTime ExpireTime { get; set; }
    public DateTime CreatedAt { get; set; }
}

public class BackendStatusResponse
{
    public bool IsBlacklisted { get; set; }
    public bool HasCard { get; set; }
    public bool CardExpired { get; set; }
    public string ExpireText { get; set; } = string.Empty;
    public string BoundCard { get; set; } = string.Empty;
}

public class SecureEnvelope
{
    public string Payload { get; set; } = string.Empty;
    public string Iv { get; set; } = string.Empty;
    public long Ts { get; set; }
    public string Sig { get; set; } = string.Empty;
}

public class StatusPayload
{
    public string OpenId { get; set; } = string.Empty;
}

public class BindPayload
{
    public string OpenId { get; set; } = string.Empty;
    public string CardNumber { get; set; } = string.Empty;
}
