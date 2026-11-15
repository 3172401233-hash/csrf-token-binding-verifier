import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CsrfTokenService, CsrfError, ERRORS, MemoryNonceStore } from '../lib/index.js';
import { createFakeClock } from './helpers.js';

const OLD = { version: 'v1', secret: 'old-secret-key-0123456789abcdef', current: false };
const NEW = { version: 'v2', secret: 'new-secret-key-abcdef0123456789', current: true };

test('轮换重叠期：旧版本 token 仍可验证，新签发使用新版本', async () => {
  const clock = createFakeClock();
  const oldService = new CsrfTokenService({
    clock,
    ttlMs: 60_000,
    secrets: [
      { ...OLD, current: true }
    ]
  });
  const legacy = oldService.issue({ sessionId: 'sess-1', userId: 'user-1' });
  assert.equal(legacy.keyVersion, 'v1');

  const rotated = oldService.rotateSecrets([OLD, NEW]);
  assert.equal(rotated.currentKeyVersion, 'v2');

  const legacyResult = await rotated.verify(legacy.token, { sessionId: 'sess-1', userId: 'user-1' });
  assert.equal(legacyResult.keyVersion, 'v1');

  const fresh = rotated.issue({ sessionId: 'sess-1', userId: 'user-1' });
  assert.equal(fresh.keyVersion, 'v2');
  const freshResult = await rotated.verify(fresh.token, { sessionId: 'sess-1', userId: 'user-1' });
  assert.equal(freshResult.valid, true);
});

test('旧 key 能验签也不能绕过会话绑定：旧版本 token 在新会话下仍被拒', async () => {
  const clock = createFakeClock();
  const oldService = new CsrfTokenService({
    clock,
    ttlMs: 60_000,
    secrets: [{ ...OLD, current: true }]
  });
  const legacy = oldService.issue({ sessionId: 'sess-1', userId: 'user-1' });

  const rotated = oldService.rotateSecrets([OLD, NEW]);
  await assert.rejects(
    rotated.verify(legacy.token, { sessionId: 'attacker-session', userId: 'user-1' }),
    (error) => error instanceof CsrfError && error.code === ERRORS.SESSION_MISMATCH
  );
});

test('旧 key 能验签也不能绕过用户绑定', async () => {
  const clock = createFakeClock();
  const oldService = new CsrfTokenService({
    clock,
    ttlMs: 60_000,
    secrets: [{ ...OLD, current: true }]
  });
  const legacy = oldService.issue({ sessionId: 'sess-1', userId: 'user-1' });

  const rotated = oldService.rotateSecrets([OLD, NEW]);
  await assert.rejects(
    rotated.verify(legacy.token, { sessionId: 'sess-1', userId: 'user-2' }),
    (error) => error.code === ERRORS.SESSION_MISMATCH
  );
});

test('旧密钥彻底下线后，旧版本 token 因未知版本被拒（而不是静默通过）', async () => {
  const clock = createFakeClock();
  const oldService = new CsrfTokenService({
    clock,
    ttlMs: 60_000,
    secrets: [{ ...OLD, current: true }]
  });
  const legacy = oldService.issue({ sessionId: 'sess-1' });

  const retired = oldService.rotateSecrets([NEW]);
  await assert.rejects(
    retired.verify(legacy.token, { sessionId: 'sess-1' }),
    (error) => error.code === ERRORS.UNKNOWN_KEY_VERSION
  );
});

test('轮换期间共享 nonce 存储，旧版本 token 消费后不能在新服务上重放', async () => {
  const clock = createFakeClock();
  const sharedStore = new MemoryNonceStore({ clock });
  const oldService = new CsrfTokenService({
    clock,
    ttlMs: 60_000,
    nonceStore: sharedStore,
    secrets: [{ ...OLD, current: true }]
  });
  const legacy = oldService.issue({ sessionId: 'sess-1' });

  const rotated = oldService.rotateSecrets([OLD, NEW]);
  const first = await rotated.verify(legacy.token, { sessionId: 'sess-1' });
  assert.equal(first.valid, true);

  await assert.rejects(
    rotated.verify(legacy.token, { sessionId: 'sess-1' }),
    (error) => error.code === ERRORS.REPLAY
  );
});

test('伪造不存在的密钥版本直接拒绝', async () => {
  const clock = createFakeClock();
  const service = new CsrfTokenService({ clock, ttlMs: 60_000, secrets: [NEW] });
  const issued = service.issue({ sessionId: 'sess-1' });
  const [, payloadB64, mac] = issued.token.split('.');
  await assert.rejects(
    service.verify(`v999.${payloadB64}.${mac}`, { sessionId: 'sess-1' }),
    (error) => error.code === ERRORS.UNKNOWN_KEY_VERSION
  );
});

test('配置非法的 secrets 时抛出 TypeError', () => {
  assert.throws(() => new CsrfTokenService({ secrets: [] }), TypeError);
  assert.throws(
    () => new CsrfTokenService({ secrets: [{ version: 'v1', secret: 'short' }] }),
    TypeError
  );
  assert.throws(
    () => new CsrfTokenService({
      secrets: [
        { version: 'v1', secret: 'old-secret-key-0123456789abcdef' },
        { version: 'v1', secret: 'new-secret-key-abcdef0123456789' }
      ]
    }),
    TypeError
  );
});
