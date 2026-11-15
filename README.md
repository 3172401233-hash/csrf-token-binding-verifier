# csrf-token-binding-verifier

零依赖的 Node.js CSRF 防护库。Token 使用 HMAC-SHA256 绑定**会话、用户、用途和签发时间**，
支持可配置 TTL、一次性消费、密钥新旧重叠轮换、Origin/Referer 来源校验，以及时钟回拨保护。

## 防护分层：SameSite 与 CSRF token 各负责什么

CSRF 防护是纵深防御，两层机制解决的问题不同，**不能互相替代**：

| 层级 | 机制 | 负责的防护 | 覆盖不到的场景 |
| --- | --- | --- | --- |
| 浏览器层 | Cookie 的 `SameSite=Lax/Strict` | 跨站请求默认不携带会话 Cookie，从源头让跨站请求“未认证” | 同站子域名发起的攻击、顶层 GET 导航（Lax）、旧浏览器、被显式设为 `SameSite=None` 的 Cookie |
| 应用层 | 本库的 CSRF token + Origin/Referer 校验 | 即使 Cookie 被携带，攻击者拿不到绑定当前会话的有效 token；Origin 策略再拦一层跨站来源 | 不负责 XSS（XSS 能读取 token，需另做 CSP/输出编码） |

要点：

- `SameSite` 是**浏览器对 Cookie 的自动行为**，无需业务代码，但依赖浏览器实现且存在同站（same-site）而非同源（same-origin）的粒度局限。
- CSRF token 是**服务端密码学校验**：本库 token 与 `sessionId`/`userId`/`purpose` 强绑定，换会话、换用户、换操作用途都会失效，且默认一次性消费。
- Origin/Referer 校验是 token 之外的独立一道闸：跨站来源在 token 校验之前就被拒绝。
- 推荐配置：会话 Cookie 使用 `HttpOnly; Secure; SameSite=Lax`（敏感操作可用 `Strict`），同时所有状态变更接口接入本库中间件。

## Token 结构

```
<keyVersion>.<base64url(payload)>.<base64url(HMAC-SHA256)>
```

payload 字段：

- `sid`：会话 ID（绑定）
- `uid`：用户 ID（绑定）
- `pur`：用途，例如 `transfer`、`delete-account`（绑定）
- `iat` / `exp`：签发与过期时间（毫秒）
- `jti`：每次签发唯一的随机 ID，用于一次性消费防重放

HMAC 覆盖 `keyVersion + payload`。校验时**按 token 自带的版本号取对应密钥**重新计算签名，
签名通过后仍独立执行会话/用户/用途绑定检查——旧密钥在轮换重叠期可以验签，但绝不绕过绑定。

## 安装与快速使用

```js
import {
  CsrfTokenService,
  OriginPolicy,
  createCsrfMiddleware
} from 'csrf-token-binding-verifier';

const csrf = new CsrfTokenService({
  // 轮换重叠期：v1 仍可验签，v2 用于新签发
  secrets: [
    { version: 'v1', secret: process.env.CSRF_SECRET_OLD, current: false },
    { version: 'v2', secret: process.env.CSRF_SECRET_NEW, current: true }
  ],
  ttlMs: 15 * 60 * 1000, // token 有效期
  singleUse: true        // 一次性消费，默认开启
});

const originPolicy = new OriginPolicy({
  allowedOrigins: ['https://example.com']
});

const middleware = createCsrfMiddleware(csrf, originPolicy, {
  getSession: (req) => req.session,
  getPurpose: (req) => req.route?.csrfPurpose || 'csrf'
});

// 渲染表单时签发（多标签页各自调用，jti 互不相同）
app.get('/transfer/form', (req, res) => {
  const { token } = csrf.issue({
    sessionId: req.session.id,
    userId: req.session.userId,
    purpose: 'transfer'
  });
  res.json({ token });
});

// 状态变更接口：先 Origin，再会话，再 token
app.post('/transfer', middleware, handler);
```

token 可通过 `X-CSRF-Token`（或 `X-XSRF-Token`）请求头，或请求体 `_csrf` 字段提交。

## API

### `new CsrfTokenService(options)`

- `secrets`（必填）：`{ version: string, secret: string(>=16), current?: boolean }[]`，
  `current: true` 的条目用于签发；未指定时取数组第一项。
- `ttlMs`：有效期，默认 15 分钟。
- `singleUse`：是否一次性消费，默认 `true`。
- `futureLeewayMs`：容忍的未来签发时间偏差（时钟偏移），默认 60 秒。
- `nonceStore`：自定义一次性存储，需实现 `consume(jti, expiresAtMs): Promise<boolean>`，
  多进程/多实例部署时应替换为 Redis 等共享存储（如 `SET key NX PX ttl`）。
- `clock`：注入自定义时钟（测试用），生产环境默认使用受单调高水位保护的系统时钟。

方法：

- `issue({ sessionId, userId?, purpose? })` → `{ token, jti, issuedAt, expiresAt, keyVersion }`
- `verify(token, { sessionId, userId?, purpose? })` → 成功返回校验结果，失败抛 `CsrfError`
- `rotateSecrets(secrets)`：返回新服务实例，共享原 nonce 存储与单调时钟，平滑轮换
- `sweepExpiredNonces()`：清理已过期的 nonce 记录

### `new OriginPolicy(options)`

- `allowedOrigins`（必填）：允许的精确来源列表，按 `协议+主机+端口` 匹配。
- `requireOrigin`：缺失 Origin 与 Referer 时是否拒绝，默认 `true`（拒绝）。
- `allowNullOrigin`：是否允许 `Origin: null`（沙箱 iframe 等），默认 `false`。

安全方法（GET/HEAD/OPTIONS/TRACE）跳过来源校验；不安全方法优先校验 Origin，
缺失时回退解析 Referer 的 origin 再比对。

## 攻击场景与对应防护

| 攻击/异常场景 | 防护行为 | 错误码 |
| --- | --- | --- |
| 跨站伪造提交（evil.com 发起） | Origin/Referer 不在允许列表，校验前拦截 | `ERR_CSRF_ORIGIN_DENIED` |
| 来源头全部缺失 | 默认拒绝 | `ERR_CSRF_NO_ORIGIN` |
| 篡改 token 签名/载荷 | HMAC 校验失败 | `ERR_CSRF_BAD_SIGNATURE` |
| 同浏览器换会话 / Cookie 被替换 | `sid` 绑定不匹配 | `ERR_CSRF_SESSION_MISMATCH` |
| 会话内替换用户身份 | `uid` 绑定不匹配 | `ERR_CSRF_SESSION_MISMATCH` |
| 跨操作复用 token（如转账 token 用于销户） | `pur` 绑定不匹配 | `ERR_CSRF_PURPOSE_MISMATCH` |
| token 重放 / 重复提交 | 一次性 `jti` 消费，第二次拒绝 | `ERR_CSRF_REPLAY` |
| 并发重复提交 | `consume` 原子性保证仅一次成功 | `ERR_CSRF_REPLAY` |
| 多标签页 | 每次签发独立 `jti`，各自可用且各自只可用一次 | — |
| TTL 超时 | 过期拒绝 | `ERR_CSRF_EXPIRED` |
| 时钟回拨 | 单调时钟高水位 + TTL 判定，过期 token 无法复活 | `ERR_CSRF_EXPIRED` |
| 伪造未来签发时间 | 超过 `futureLeewayMs` 拒绝 | `ERR_CSRF_FUTURE_TOKEN` |
| 会话 Cookie 丢失 | 无会话无法建立绑定，拒绝 | `ERR_CSRF_NO_SESSION` |
| 密钥轮换期间的旧 token | 按 token 版本选 key 验签，绑定检查不放松 | — |
| 旧密钥彻底下线 | 未知版本直接拒绝，绝不静默通过 | `ERR_CSRF_UNKNOWN_KEY_VERSION` |

## 密钥轮换

1. 重叠期：配置中同时保留旧 `version`（`current: false`）与新 `version`（`current: true`）。
   新请求用新 key 签发，已流通的旧 token 在 TTL 内仍可验签。
2. 等待超过最大 TTL 后，从配置移除旧版本；此后旧 token 返回 `ERR_CSRF_UNKNOWN_KEY_VERSION`。
3. 也可调用 `rotateSecrets()` 得到共享 nonce 存储的新实例，保证轮换窗口内重放防护连续。

注意：token 自带版本号，校验只使用该版本对应的密钥；不存在“用旧 key 验过就跳过会话绑定”的路径。

## 部署注意

- 单进程默认使用内存 nonce 存储；多实例部署必须注入共享存储（Redis `SET NX PX` 等），
  否则一次性消费只在单实例内生效。
- 反向代理后确保信任代理并正确读取 `Origin`/`Referer`。
- 会话 Cookie 建议 `HttpOnly; Secure; SameSite=Lax`，与本库构成双层防护。

## 测试

```bash
npm test        # 等价于 node --test
```

测试覆盖：跨站来源、字段篡改、token 重放、并发提交、多标签页、时钟回拨、Cookie 丢失、
会话/用户/用途替换、TTL 边界以及密钥轮换边界。
