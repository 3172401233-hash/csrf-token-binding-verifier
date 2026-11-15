import { test } from 'node:test';
import assert from 'node:assert/strict';
import { OriginPolicy, CsrfError, ERRORS } from '../lib/index.js';
import { makeReq } from './helpers.js';

function createPolicy(overrides = {}) {
  return new OriginPolicy({
    allowedOrigins: ['https://example.com', 'https://admin.example.com'],
    ...overrides
  });
}

test('安全方法跳过来源校验', () => {
  const policy = createPolicy();
  for (const method of ['GET', 'HEAD', 'OPTIONS']) {
    const result = policy.checkRequest(makeReq({ method, headers: {} }));
    assert.equal(result.enforced, false);
  }
});

test('同站 Origin 通过校验', () => {
  const policy = createPolicy();
  const result = policy.checkRequest(
    makeReq({ headers: { origin: 'https://example.com' } })
  );
  assert.deepEqual(result, { enforced: true, source: 'origin', origin: 'https://example.com' });
});

test('跨站 Origin 被拒绝（跨站提交防护）', () => {
  const policy = createPolicy();
  for (const origin of [
    'https://evil.com',
    'https://example.com.evil.com',
    'http://example.com',
    'https://example.com:8443'
  ]) {
    assert.throws(
      () => policy.checkRequest(makeReq({ headers: { origin } })),
      (error) => error instanceof CsrfError && error.code === ERRORS.ORIGIN_DENIED
    );
  }
});

test('Origin 缺失时回退 Referer，跨站 Referer 被拒绝', () => {
  const policy = createPolicy();
  const ok = policy.checkRequest(
    makeReq({ headers: { referer: 'https://example.com/transfer/confirm?x=1' } })
  );
  assert.equal(ok.source, 'referer');

  assert.throws(
    () => policy.checkRequest(
      makeReq({ headers: { referer: 'https://evil.com/csrf-attack' } })
    ),
    (error) => error.code === ERRORS.ORIGIN_DENIED
  );
});

test('Origin 与 Referer 同时缺失默认拒绝', () => {
  const policy = createPolicy();
  assert.throws(
    () => policy.checkRequest(makeReq({ headers: {} })),
    (error) => error.code === ERRORS.NO_ORIGIN
  );
});

test('requireOrigin=false 时允许缺失来源头，但存在头时仍严格校验', () => {
  const policy = createPolicy({ requireOrigin: false });
  const skipped = policy.checkRequest(makeReq({ headers: {} }));
  assert.equal(skipped.enforced, false);

  assert.throws(
    () => policy.checkRequest(makeReq({ headers: { origin: 'https://evil.com' } })),
    (error) => error.code === ERRORS.ORIGIN_DENIED
  );
});

test('null Origin（沙箱 iframe 等）默认拒绝', () => {
  const policy = createPolicy();
  assert.throws(
    () => policy.checkRequest(makeReq({ headers: { origin: 'null' } })),
    (error) => error.code === ERRORS.ORIGIN_DENIED
  );
});

test('结尾斜杠与端口规范化不影响匹配', () => {
  const policy = new OriginPolicy({ allowedOrigins: ['https://example.com/'] });
  const result = policy.checkRequest(
    makeReq({ headers: { origin: 'https://example.com' } })
  );
  assert.equal(result.origin, 'https://example.com');
});

test('空的允许列表无法构造策略', () => {
  assert.throws(() => new OriginPolicy({ allowedOrigins: [] }), TypeError);
});
