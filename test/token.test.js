import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CsrfTokenService, CsrfError, ERRORS } from '../lib/index.js';
import { createFakeClock, baseSecrets } from './helpers.js';

function createService(overrides = {}) {
  const clock = createFakeClock();
  return {
    clock,
    service: new CsrfTokenService({ ...baseSecrets(clock), ...overrides })
  };
}

test('签发的 token 可被同会话同用户同用途校验通过', async () => {
  const { service } = createService();
  const issued = service.issue({ sessionId: 'sess-1', userId: 'user-1', purpose: 'transfer' });
  const result = await service.verify(issued.token, {
    sessionId: 'sess-1',
    userId: 'user-1',
    purpose: 'transfer'
  });
  assert.equal(result.valid, true);
  assert.equal(result.keyVersion, 'v2');
  assert.equal(result.jti, issued.jti);
});

test('token 结构携带密钥版本，且默认使用 current 版本签发', () => {
  const { service } = createService();
  const issued = service.issue({ sessionId: 'sess-1' });
  assert.equal(issued.token.split('.').length, 3);
  assert.equal(issued.token.startsWith('v2.'), true);
  assert.equal(service.currentKeyVersion, 'v2');
});

test('篡改签名被拒绝', async () => {
  const { service } = createService();
  const issued = service.issue({ sessionId: 'sess-1' });
  const tampered = `${issued.token.slice(0, -4)}AAAA`;
  await assert.rejects(
    service.verify(tampered, { sessionId: 'sess-1' }),
    (error) => error instanceof CsrfError && error.code === ERRORS.BAD_SIGNATURE
  );
});

test('篡改载荷字段后签名失效', async () => {
  const { service } = createService();
  const issued = service.issue({ sessionId: 'sess-1', userId: 'user-1' });
  const [version, , mac] = issued.token.split('.');
  const forgedPayload = Buffer.from(
    JSON.stringify({ sid: 'sess-1', uid: 'attacker', pur: 'csrf', iat: 1, exp: 9, jti: 'x' })
  ).toString('base64url');
  await assert.rejects(
    service.verify(`${version}.${forgedPayload}.${mac}`, { sessionId: 'sess-1' }),
    (error) => error.code === ERRORS.BAD_SIGNATURE
  );
});

test('会话替换：token 绑定的会话与当前会话不一致时拒绝', async () => {
  const { service } = createService();
  const issued = service.issue({ sessionId: 'sess-1', userId: 'user-1' });
  await assert.rejects(
    service.verify(issued.token, { sessionId: 'sess-2', userId: 'user-1' }),
    (error) => error.code === ERRORS.SESSION_MISMATCH
  );
});

test('同一浏览器更换 Origin 不影响 token，但会话 ID 变化即失效（token 不绑定 Origin）', async () => {
  const { service } = createService();
  const issued = service.issue({ sessionId: 'sess-1', userId: 'user-1' });
  const result = await service.verify(issued.token, { sessionId: 'sess-1', userId: 'user-1' });
  assert.equal(result.valid, true);
});

test('用户不一致时拒绝，防止会话内身份替换', async () => {
  const { service } = createService();
  const issued = service.issue({ sessionId: 'sess-1', userId: 'user-1' });
  await assert.rejects(
    service.verify(issued.token, { sessionId: 'sess-1', userId: 'user-2' }),
    (error) => error.code === ERRORS.SESSION_MISMATCH
  );
});

test('用途不匹配时拒绝，防止跨操作复用 token', async () => {
  const { service } = createService();
  const issued = service.issue({ sessionId: 'sess-1', purpose: 'transfer' });
  await assert.rejects(
    service.verify(issued.token, { sessionId: 'sess-1', purpose: 'delete-account' }),
    (error) => error.code === ERRORS.PURPOSE_MISMATCH
  );
});

test('TTL 边界：未过期通过，到达过期时间拒绝', async () => {
  const clock = createFakeClock();
  const service = new CsrfTokenService({ ...baseSecrets(clock), ttlMs: 60_000 });
  const issued = service.issue({ sessionId: 'sess-1' });
  assert.equal(issued.expiresAt - issued.issuedAt, 60_000);

  const fresh = new CsrfTokenService({ ...baseSecrets(clock), ttlMs: 60_000 });
  clock.set(issued.issuedAt + 59_000);
  const before = await fresh.verify(issued.token, { sessionId: 'sess-1' });
  assert.equal(before.valid, true);

  const expired = new CsrfTokenService({ ...baseSecrets(clock), ttlMs: 60_000 });
  clock.set(issued.issuedAt + 60_000);
  await assert.rejects(
    expired.verify(issued.token, { sessionId: 'sess-1' }),
    (error) => error.code === ERRORS.EXPIRED
  );
});

test('时钟回拨不会延长 token 有效期', async () => {
  const clock = createFakeClock();
  const service = new CsrfTokenService({ ...baseSecrets(clock), ttlMs: 10_000 });
  const issued = service.issue({ sessionId: 'sess-1' });

  clock.advance(10_001);
  await assert.rejects(
    service.verify(issued.token, { sessionId: 'sess-1' }),
    (error) => error.code === ERRORS.EXPIRED
  );

  clock.rollback(50_000);
  await assert.rejects(
    service.verify(issued.token, { sessionId: 'sess-1' }),
    (error) => error.code === ERRORS.EXPIRED
  );
});

test('时钟回拨后新签发的 token 不会被误判为未来 token', async () => {
  const clock = createFakeClock();
  const service = new CsrfTokenService({ ...baseSecrets(clock) });
  clock.advance(120_000);
  const issued = service.issue({ sessionId: 'sess-1' });
  clock.rollback(90_000);
  const result = await service.verify(issued.token, { sessionId: 'sess-1' });
  assert.equal(result.valid, true);
});

test('超过未来容差的 token 被拒绝（伪造未来 iat 的 token）', async () => {
  const { createHmac } = await import('node:crypto');
  const clock = createFakeClock();
  const service = new CsrfTokenService({
    ...baseSecrets(clock),
    futureLeewayMs: 5_000
  });

  const now = clock.now();
  const payloadB64 = Buffer.from(JSON.stringify({
    sid: 'sess-1',
    uid: '',
    pur: 'csrf',
    iat: now + 60_000,
    exp: now + 120_000,
    jti: 'future-jti'
  })).toString('base64url');
  const mac = createHmac('sha256', baseSecrets(clock).secrets[1].secret)
    .update(`v2.${payloadB64}`)
    .digest('base64url');

  await assert.rejects(
    service.verify(`v2.${payloadB64}.${mac}`, { sessionId: 'sess-1' }),
    (error) => error.code === ERRORS.FUTURE_TOKEN
  );
});

test('畸形 token 被拒绝', async () => {
  const { service } = createService();
  for (const bad of ['', 'a.b', 'a..c', 'v2.abc.', 'not-a-token', 123, null]) {
    await assert.rejects(
      service.verify(bad, { sessionId: 'sess-1' }),
      (error) => error instanceof CsrfError
    );
  }
});

test('缺少会话绑定时抛出 NO_SESSION', async () => {
  const { service } = createService();
  const issued = service.issue({ sessionId: 'sess-1' });
  await assert.rejects(
    service.verify(issued.token, { sessionId: '' }),
    (error) => error.code === ERRORS.NO_SESSION
  );
  assert.throws(
    () => service.issue({ sessionId: '' }),
    (error) => error.code === ERRORS.NO_SESSION
  );
});
