export class CsrfError extends Error {
  constructor(code, message, { statusCode = 403 } = {}) {
    super(message);
    this.name = 'CsrfError';
    this.code = code;
    this.statusCode = statusCode;
  }
}

export const ERRORS = Object.freeze({
  MALFORMED: 'ERR_CSRF_MALFORMED',
  UNKNOWN_KEY_VERSION: 'ERR_CSRF_UNKNOWN_KEY_VERSION',
  BAD_SIGNATURE: 'ERR_CSRF_BAD_SIGNATURE',
  SESSION_MISMATCH: 'ERR_CSRF_SESSION_MISMATCH',
  PURPOSE_MISMATCH: 'ERR_CSRF_PURPOSE_MISMATCH',
  EXPIRED: 'ERR_CSRF_EXPIRED',
  FUTURE_TOKEN: 'ERR_CSRF_FUTURE_TOKEN',
  REPLAY: 'ERR_CSRF_REPLAY',
  ORIGIN_DENIED: 'ERR_CSRF_ORIGIN_DENIED',
  NO_ORIGIN: 'ERR_CSRF_NO_ORIGIN',
  NO_SESSION: 'ERR_CSRF_NO_SESSION',
  NO_TOKEN: 'ERR_CSRF_NO_TOKEN'
});
