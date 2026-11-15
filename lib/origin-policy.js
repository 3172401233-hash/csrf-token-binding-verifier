import { CsrfError, ERRORS } from './errors.js';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'TRACE']);

function normalizeOrigin(value) {
  const trimmed = String(value).trim();
  return trimmed.endsWith('/') ? trimmed.slice(0, -1) : trimmed;
}

export class OriginPolicy {
  #allowed;
  #requireOrigin;
  #allowSameOriginNull;

  constructor({
    allowedOrigins = [],
    requireOrigin = true,
    allowNullOrigin = false
  } = {}) {
    if (!Array.isArray(allowedOrigins) || allowedOrigins.length === 0) {
      throw new TypeError('OriginPolicy 需要至少一个 allowedOrigins');
    }
    this.#allowed = new Set(allowedOrigins.map(normalizeOrigin));
    this.#requireOrigin = requireOrigin;
    this.#allowSameOriginNull = allowNullOrigin;
  }

  allows(origin) {
    if (origin === undefined || origin === null || origin === '') {
      return false;
    }
    const value = normalizeOrigin(origin);
    if (value === 'null') {
      return this.#allowSameOriginNull && this.#allowed.has('null');
    }
    return this.#allowed.has(value);
  }

  checkRequest(req) {
    const method = String(req.method || 'GET').toUpperCase();
    if (SAFE_METHODS.has(method)) {
      return { enforced: false, reason: 'safe-method' };
    }

    const origin = req.headers && typeof req.headers.origin === 'string'
      ? req.headers.origin
      : undefined;

    if (origin !== undefined) {
      if (!this.allows(origin)) {
        throw new CsrfError(
          ERRORS.ORIGIN_DENIED,
          `Origin 不在允许列表中: ${origin}`
        );
      }
      return { enforced: true, source: 'origin', origin: normalizeOrigin(origin) };
    }

    const referer = req.headers && typeof req.headers.referer === 'string'
      ? req.headers.referer
      : undefined;

    if (referer === undefined) {
      if (this.#requireOrigin) {
        throw new CsrfError(
          ERRORS.NO_ORIGIN,
          '跨站校验缺少 Origin 与 Referer 头'
        );
      }
      return { enforced: false, reason: 'origin-not-required' };
    }

    let refererOrigin;
    try {
      refererOrigin = new URL(referer).origin;
    } catch {
      throw new CsrfError(ERRORS.ORIGIN_DENIED, `Referer 无法解析: ${referer}`);
    }

    if (!this.allows(refererOrigin)) {
      throw new CsrfError(
        ERRORS.ORIGIN_DENIED,
        `Referer 来源不在允许列表中: ${refererOrigin}`
      );
    }
    return { enforced: true, source: 'referer', origin: refererOrigin };
  }
}
