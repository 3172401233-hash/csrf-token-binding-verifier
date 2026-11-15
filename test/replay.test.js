import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CsrfTokenService, CsrfError, ERRORS, MemoryNonceStore } from '../lib/index.js';
import { createFakeClock, baseSecrets } from './helpers.js';

function createService(overrides = {}) {
  const clock = createFakeClock();
  return {
    clock,
    service: new CsrfTokenService({ ...baseSecrets(clock), ...overrides })
  };
}

test('一次性消费：同一 token 第二次提交被拒绝（关闭重复使用窗口）', async () => {
  const { service } = createService();
  const issued = service.issue({ sessionId: 'sess-1' });

  const first = await service.verify(issued.token, { sessionId: 'sess-1' });
  assert.equal(first.valid, true);

  await assert.rejects(
    service.verify(issued.token, { sessionId: 'sess-1' }),
    (error) => error instanceof CsrfError && error.code === ERRORS.REPLAY
  );
});

test('并发提交：只有一个请求消费成功，其余全部拒绝', async () => {
  const { service } = createService();
  const issued = service.issue({ sessionId: 'sess-1' });

  const outcomes = await Promise.allSettled(
    Array.from({ length: 8 }, () => service.verify(issued.token, { sessionId: 'sess-1' }))
  );
  const fulfilled = outcomes.filter((outcome) => outcome.status === 'fulfilled');
  const rejected = outcomes.filter((outcome) => outcome.status === 'rejected');
  assert.equal(fulfilled.length, 1);
  assert.equal(rejected.length, 7);
  assert.ok(rejected.every((outcome) => outcome.reason.code === ERRORS.REPLAY));
});

test('异步 nonce 存储下并发消费仍然只有一次成功', async () => {
  const clock = createFakeClock();
  let gate;
  const gatePromise = new Promise((resolve) => {
    gate = resolve;
  });
  const slowStore = {
    consume: (jti, expiresAt) => gatePromise.then(() => memory.consume(jti, expiresAt))
  };
  const memory = new MemoryNonceStore({ clock });

  const service = new CsrfTokenService({
    ...baseSecrets(clock),
    nonceStore: slowStore
  });
  const issued = service.issue({ sessionId: 'sess-1' });

  const pending = Promise.allSettled(
    Array.from({ length: 4 }, () => service.verify(issued.token, { sessionId: 'sess-1' }))
  );
  await Promise.resolve();
  gate();
  const outcomes = await pending;

  assert.equal(outcomes.filter((o) => o.status === 'fulfilled').length, 1);
  assert.equal(outcomes.filter((o) => o.status === 'rejected').length, 3);
});

test('多标签页：每个页面各自签发独立 jti，互不影响且各自只能用一次', async () => {
  const { service } = createService();
  const tabA = service.issue({ sessionId: 'sess-1', userId: 'user-1' });
  const tabB = service.issue({ sessionId: 'sess-1', userId: 'user-1' });
  assert.notEqual(tabA.jti, tabB.jti);

  const resultA = await service.verify(tabA.token, { sessionId: 'sess-1', userId: 'user-1' });
  const resultB = await service.verify(tabB.token, { sessionId: 'sess-1', userId: 'user-1' });
  assert.equal(resultA.valid, true);
  assert.equal(resultB.valid, true);

  await assert.rejects(
    service.verify(tabA.token, { sessionId: 'sess-1', userId: 'user-1' }),
    (error) => error.code === ERRORS.REPLAY
  );
  await assert.rejects(
    service.verify(tabB.token, { sessionId: 'sess-1', userId: 'user-1' }),
    (error) => error.code === ERRORS.REPLAY
  );
});

test('关闭 singleUse 后允许 TTL 内重复校验，但过期仍拒绝', async () => {
  const clock = createFakeClock();
  const service = new CsrfTokenService({
    ...baseSecrets(clock),
    singleUse: false
  });
  const issued = service.issue({ sessionId: 'sess-1' });

  assert.equal((await service.verify(issued.token, { sessionId: 'sess-1' })).valid, true);
  assert.equal((await service.verify(issued.token, { sessionId: 'sess-1' })).valid, true);

  clock.advance(60_001);
  await assert.rejects(
    service.verify(issued.token, { sessionId: 'sess-1' }),
    (error) => error.code === ERRORS.EXPIRED
  );
});

test('nonce 存储在过期后清理，避免无限增长', async () => {
  const clock = createFakeClock();
  const store = new MemoryNonceStore({ clock, sweepThreshold: 100 });
  const service = new CsrfTokenService({ ...baseSecrets(clock), ttlMs: 10_000, nonceStore: store });

  for (let index = 0; index < 5; index += 1) {
    const issued = service.issue({ sessionId: 'sess-1' });
    await service.verify(issued.token, { sessionId: 'sess-1' });
  }
  assert.equal(store.size, 5);

  clock.advance(10_001);
  service.sweepExpiredNonces();
  assert.equal(store.size, 0);
});

test('过期 token 不会写入 nonce，重放始终报 EXPIRED', async () => {
  const clock = createFakeClock();
  const store = new MemoryNonceStore({ clock });
  const service = new CsrfTokenService({ ...baseSecrets(clock), ttlMs: 10_000, nonceStore: store });
  const issued = service.issue({ sessionId: 'sess-1' });

  clock.advance(10_001);
  for (let index = 0; index < 2; index += 1) {
    await assert.rejects(
      service.verify(issued.token, { sessionId: 'sess-1' }),
      (error) => error.code === ERRORS.EXPIRED
    );
  }
  assert.equal(store.size, 0);
});
