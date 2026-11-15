import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  CsrfTokenService,
  OriginPolicy,
  createCsrfMiddleware,
  CsrfError,
  ERRORS
} from '../lib/index.js';
import { createFakeClock, makeReq, runMiddleware, baseSecrets } from './helpers.js';

function setup(overrides = {}) {
  const clock = createFakeClock();
  const service = new CsrfTokenService({ ...baseSecrets(clock), ...overrides });
  const policy = new OriginPolicy({ allowedOrigins: ['https://example.com'] });
  const middleware = createCsrfMiddleware(service, policy);
  return { clock, service, policy, middleware };
}

test('完整请求链路：同站来源 + 有效 token 通过并可换发新 token', async () => {
  const { service, middleware } = setup();
  const issued = service.issue({ sessionId: 'sess-1', userId: 'user-1' });
  const req = makeReq({
    headers: { origin: 'https://example.com', 'x-csrf-token': issued.token }
  });

  const handled = await runMiddleware(middleware, req);
  assert.equal(handled.csrfVerification.valid, true);
  assert.equal(typeof handled.csrfToken(), 'string');
});

test('跨站来源请求在 token 校验前即被拦截', async () => {
  const { service, middleware } = setup();
  const issued = service.issue({ sessionId: 'sess-1', userId: 'user-1' });
  const req = makeReq({
    headers: { origin: 'https://evil.com', 'x-csrf-token': issued.token }
  });

  await assert.rejects(
    runMiddleware(middleware, req),
    (error) => error instanceof CsrfError && error.code === ERRORS.ORIGIN_DENIED
  );
});

test('Cookie 丢失导致无会话时拒绝，而不是放行', async () => {
  const { service, middleware } = setup();
  const issued = service.issue({ sessionId: 'sess-1', userId: 'user-1' });
  const req = makeReq({
    headers: { origin: 'https://example.com', 'x-csrf-token': issued.token },
    session: null
  });

  await assert.rejects(
    runMiddleware(middleware, req),
    (error) => error.code === ERRORS.NO_SESSION
  );
});

test('会话 Cookie 被替换成另一个会话时 token 绑定失败', async () => {
  const { service, middleware } = setup();
  const issued = service.issue({ sessionId: 'sess-1', userId: 'user-1' });
  const req = makeReq({
    headers: { origin: 'https://example.com', 'x-csrf-token': issued.token },
    session: { id: 'sess-hijacked', userId: 'user-1' }
  });

  await assert.rejects(
    runMiddleware(middleware, req),
    (error) => error.code === ERRORS.SESSION_MISMATCH
  );
});

test('重放请求在中间件层被拒', async () => {
  const { service, middleware } = setup();
  const issued = service.issue({ sessionId: 'sess-1', userId: 'user-1' });
  const headers = { origin: 'https://example.com', 'x-csrf-token': issued.token };

  await runMiddleware(middleware, makeReq({ headers }));
  await assert.rejects(
    runMiddleware(middleware, makeReq({ headers: { ...headers } })),
    (error) => error.code === ERRORS.REPLAY
  );
});

test('缺少 token 返回 NO_TOKEN', async () => {
  const { middleware } = setup();
  const req = makeReq({ headers: { origin: 'https://example.com' } });
  await assert.rejects(
    runMiddleware(middleware, req),
    (error) => error.code === ERRORS.NO_TOKEN
  );
});

test('支持从请求体 _csrf 字段提取 token', async () => {
  const { service, middleware } = setup();
  const issued = service.issue({ sessionId: 'sess-1', userId: 'user-1' });
  const req = makeReq({
    headers: { origin: 'https://example.com' },
    body: { _csrf: issued.token }
  });
  const handled = await runMiddleware(middleware, req);
  assert.equal(handled.csrfVerification.valid, true);
});

test('按用途隔离的中间件拒绝跨用途 token', async () => {
  const clock = createFakeClock();
  const service = new CsrfTokenService({ ...baseSecrets(clock) });
  const policy = new OriginPolicy({ allowedOrigins: ['https://example.com'] });
  const middleware = createCsrfMiddleware(service, policy, {
    getPurpose: (req) => req.purpose
  });
  const issued = service.issue({
    sessionId: 'sess-1',
    userId: 'user-1',
    purpose: 'transfer'
  });
  const req = makeReq({
    headers: { origin: 'https://example.com', 'x-csrf-token': issued.token }
  });
  req.purpose = 'delete-account';

  await assert.rejects(
    runMiddleware(middleware, req),
    (error) => error.code === ERRORS.PURPOSE_MISMATCH
  );
});

test('并发重复提交经过中间件只有一次成功', async () => {
  const { service, middleware } = setup();
  const issued = service.issue({ sessionId: 'sess-1', userId: 'user-1' });
  const outcomes = await Promise.allSettled(
    Array.from({ length: 5 }, () => runMiddleware(
      middleware,
      makeReq({
        headers: { origin: 'https://example.com', 'x-csrf-token': issued.token }
      })
    ))
  );
  assert.equal(outcomes.filter((o) => o.status === 'fulfilled').length, 1);
  assert.equal(outcomes.filter((o) => o.status === 'rejected').length, 4);
});
