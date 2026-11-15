import { randomUUID, timingSafeEqual, createHmac } from 'node:crypto';
import { CsrfError, ERRORS } from './errors.js';
import { createMonotonicClock } from './clock.js';
import { MemoryNonceStore } from './nonce-store.js';

const HMAC_ALGORITHM = 'sha256';
const DEFAULT_PURPOSE = 'csrf';
const DEFAULT_FUTURE_LEEWAY_MS = 60_000;

function base64UrlEncode(value) {
  return Buffer.from(value).toString('base64url');
}

function sign(keyVersion, secret, payloadB64) {
  return createHmac(HMAC_ALGORITHM, secret)
    .update(`${keyVersion}.${payloadB64}`)
    .digest('base64url');
}

function safeEqual(left, right) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }
  return timingSafeEqual(leftBuffer, rightBuffer);
}

function requireBinding(value, label) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new CsrfError(ERRORS.NO_SESSION, `${label} 缺失，无法进行 CSRF 绑定`);
  }
  return value;
}

export class CsrfTokenService {
  #keys;
  #currentVersion;
  #ttlMs;
  #singleUse;
  #futureLeewayMs;
  #nonceStore;
  #clock;

  constructor(options = {}) {
    const {
      secrets,
      ttlMs = 15 * 60 * 1000,
      singleUse = true,
      futureLeewayMs = DEFAULT_FUTURE_LEEWAY_MS,
      nonceStore,
      clock
    } = options;

    if (!Array.isArray(secrets) || secrets.length === 0) {
      throw new TypeError('secrets 必须是非空数组');
    }
    const seen = new Set();
    this.#keys = new Map();
    for (const entry of secrets) {
      if (!entry || typeof entry.version !== 'string' || !entry.version) {
        throw new TypeError('每个 secret 需要字符串类型的 version');
      }
      if (typeof entry.secret !== 'string' || entry.secret.length < 16) {
        throw new TypeError(`version=${entry.version} 的 secret 至少 16 个字符`);
      }
      if (seen.has(entry.version)) {
        throw new TypeError(`secret version 重复: ${entry.version}`);
      }
      seen.add(entry.version);
      this.#keys.set(entry.version, entry.secret);
    }

    const preferred = secrets.find((entry) => entry.current === true);
    this.#currentVersion = preferred ? preferred.version : secrets[0].version;
    if (!this.#keys.has(this.#currentVersion)) {
      throw new TypeError('current 指向的 secret 不存在');
    }

    if (!Number.isInteger(ttlMs) || ttlMs <= 0) {
      throw new TypeError('ttlMs 必须是正整数');
    }
    this.#ttlMs = ttlMs;
    this.#singleUse = singleUse === true;
    this.#futureLeewayMs = futureLeewayMs;

    const systemClock = typeof clock === 'function' ? clock : () => Date.now();
    this.#clock = createMonotonicClock(systemClock);
    this.#nonceStore = nonceStore || new MemoryNonceStore({ clock: this.#clock });
  }

  get currentKeyVersion() {
    return this.#currentVersion;
  }

  rotateSecrets(secrets) {
    const next = new CsrfTokenService({
      secrets,
      ttlMs: this.#ttlMs,
      singleUse: this.#singleUse,
      futureLeewayMs: this.#futureLeewayMs,
      nonceStore: this.#nonceStore,
      clock: this.#clock
    });
    return next;
  }

  issue({ sessionId, userId = '', purpose = DEFAULT_PURPOSE }) {
    const boundSession = requireBinding(sessionId, 'sessionId');
    const boundUser = typeof userId === 'string' ? userId : String(userId);
    const boundPurpose = requireBinding(purpose, 'purpose');

    const issuedAt = this.#clock();
    const payload = {
      sid: boundSession,
      uid: boundUser,
      pur: boundPurpose,
      iat: issuedAt,
      exp: issuedAt + this.#ttlMs,
      jti: randomUUID()
    };
    const payloadB64 = base64UrlEncode(JSON.stringify(payload));
    const mac = sign(this.#currentVersion, this.#keys.get(this.#currentVersion), payloadB64);

    return {
      token: `${this.#currentVersion}.${payloadB64}.${mac}`,
      jti: payload.jti,
      issuedAt,
      expiresAt: payload.exp,
      keyVersion: this.#currentVersion
    };
  }

  async verify(token, { sessionId, userId = '', purpose = DEFAULT_PURPOSE } = {}) {
    const boundSession = requireBinding(sessionId, 'sessionId');
    const boundUser = typeof userId === 'string' ? userId : String(userId);
    const boundPurpose = requireBinding(purpose, 'purpose');

    if (typeof token !== 'string' || token.length === 0) {
      throw new CsrfError(ERRORS.NO_TOKEN, '缺少 CSRF token');
    }

    const parts = token.split('.');
    if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
      throw new CsrfError(ERRORS.MALFORMED, 'CSRF token 格式非法');
    }
    const [keyVersion, payloadB64, providedMac] = parts;

    const secret = this.#keys.get(keyVersion);
    if (!secret) {
      throw new CsrfError(ERRORS.UNKNOWN_KEY_VERSION, `未知的 token 密钥版本: ${keyVersion}`);
    }

    const expectedMac = sign(keyVersion, secret, payloadB64);
    if (!safeEqual(expectedMac, providedMac)) {
      throw new CsrfError(ERRORS.BAD_SIGNATURE, 'CSRF token 签名不匹配');
    }

    let payload;
    try {
      const decoded = Buffer.from(payloadB64, 'base64url').toString('utf8');
      payload = JSON.parse(decoded);
    } catch {
      throw new CsrfError(ERRORS.MALFORMED, 'CSRF token 载荷无法解析');
    }

    if (!payload || typeof payload !== 'object' || typeof payload.sid !== 'string') {
      throw new CsrfError(ERRORS.MALFORMED, 'CSRF token 载荷字段缺失');
    }

    const now = this.#clock();

    if (payload.iat > now + this.#futureLeewayMs) {
      throw new CsrfError(ERRORS.FUTURE_TOKEN, 'CSRF token 签发时间在未来');
    }
    if (typeof payload.exp !== 'number' || now >= payload.exp) {
      throw new CsrfError(ERRORS.EXPIRED, 'CSRF token 已过期');
    }

    if (!safeEqual(payload.sid, boundSession)) {
      throw new CsrfError(
        ERRORS.SESSION_MISMATCH,
        'CSRF token 绑定的会话与当前会话不一致'
      );
    }
    if (!safeEqual(String(payload.uid ?? ''), boundUser)) {
      throw new CsrfError(
        ERRORS.SESSION_MISMATCH,
        'CSRF token 绑定的用户与当前用户不一致'
      );
    }
    if (!safeEqual(String(payload.pur ?? ''), boundPurpose)) {
      throw new CsrfError(
        ERRORS.PURPOSE_MISMATCH,
        'CSRF token 用途与当前操作不匹配'
      );
    }

    const jti = typeof payload.jti === 'string' ? payload.jti : '';
    if (!jti) {
      throw new CsrfError(ERRORS.MALFORMED, 'CSRF token 缺少一次性标识 jti');
    }

    if (this.#singleUse) {
      const accepted = await this.#nonceStore.consume(jti, payload.exp);
      if (!accepted) {
        throw new CsrfError(ERRORS.REPLAY, 'CSRF token 已被消费，拒绝重放');
      }
    }

    return {
      valid: true,
      jti,
      keyVersion,
      issuedAt: payload.iat,
      expiresAt: payload.exp
    };
  }

  sweepExpiredNonces() {
    return this.#nonceStore.sweep(this.#clock());
  }
}
