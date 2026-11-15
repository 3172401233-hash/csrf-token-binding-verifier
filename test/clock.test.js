import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createMonotonicClock } from '../lib/index.js';

test('单调时钟：底层时钟回拨时保持高水位，不随之后退', () => {
  let wall = 1_000;
  const monotonic = createMonotonicClock(() => wall);

  assert.equal(monotonic(), 1_000);
  wall = 2_000;
  assert.equal(monotonic(), 2_000);

  wall = 500;
  assert.equal(monotonic(), 2_000);
  assert.equal(monotonic(), 2_000);

  wall = 3_000;
  assert.equal(monotonic(), 3_000);
});

test('单调时钟：服务内时钟回拨无法让已过期 token 复活', async () => {
  let wall = 1_700_000_000_000;
  const { CsrfTokenService } = await import('../lib/index.js');
  const service = new CsrfTokenService({
    clock: () => wall,
    ttlMs: 10_000,
    secrets: [
      { version: 'v2', secret: 'new-secret-key-abcdef0123456789', current: true }
    ]
  });
  const issued = service.issue({ sessionId: 'sess-1' });

  wall += 10_001;
  await assert.rejects(
    service.verify(issued.token, { sessionId: 'sess-1' }),
    (error) => error.code === 'ERR_CSRF_EXPIRED'
  );

  wall -= 50_000;
  await assert.rejects(
    service.verify(issued.token, { sessionId: 'sess-1' }),
    (error) => error.code === 'ERR_CSRF_EXPIRED'
  );
});
