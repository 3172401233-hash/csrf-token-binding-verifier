import { CsrfError, ERRORS } from './errors.js';

const DEFAULT_HEADER_NAMES = ['csrf-token', 'x-csrf-token', 'x-xsrf-token'];

export function extractToken(req, { headerNames = DEFAULT_HEADER_NAMES, bodyField = '_csrf' } = {}) {
  for (const name of headerNames) {
    const value = req.headers && req.headers[name];
    if (typeof value === 'string' && value.length > 0) {
      return value;
    }
  }
  if (req.body && typeof req.body[bodyField] === 'string' && req.body[bodyField].length > 0) {
    return req.body[bodyField];
  }
  return null;
}

export function createCsrfMiddleware(csrf, originPolicy, options = {}) {
  const {
    getSession = (req) => req.session,
    getPurpose = () => 'csrf',
    headerNames,
    bodyField = '_csrf'
  } = options;

  return async function csrfProtection(req, res, next) {
    try {
      originPolicy.checkRequest(req);

      const session = getSession(req);
      if (!session || typeof session.id !== 'string' || session.id.length === 0) {
        throw new CsrfError(ERRORS.NO_SESSION, '请求缺少会话，CSRF 绑定无法建立');
      }

      const token = extractToken(req, { headerNames, bodyField });
      if (!token) {
        throw new CsrfError(ERRORS.NO_TOKEN, '请求缺少 CSRF token');
      }

      const result = await csrf.verify(token, {
        sessionId: session.id,
        userId: session.userId || '',
        purpose: getPurpose(req) || 'csrf'
      });

      req.csrfToken = () => csrf.issue({
        sessionId: session.id,
        userId: session.userId || '',
        purpose: getPurpose(req) || 'csrf'
      }).token;
      req.csrfVerification = result;
      next();
    } catch (error) {
      next(error);
    }
  };
}
