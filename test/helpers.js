export function createFakeClock(start = 1_700_000_000_000, stepMs = 1) {
  let time = start;
  const clock = () => {
    const current = time;
    time += stepMs;
    return current;
  };
  clock.set = (value) => {
    time = value;
  };
  clock.advance = (ms) => {
    time += ms;
    return time;
  };
  clock.rollback = (ms) => {
    time -= ms;
    return time;
  };
  clock.now = () => time;
  return clock;
}

export function makeReq({
  method = 'POST',
  headers = {},
  body = {},
  session = { id: 'sess-1', userId: 'user-1' }
} = {}) {
  return {
    method,
    headers: { ...headers },
    body,
    session
  };
}

export function noopRes() {
  return {};
}

export async function runMiddleware(middleware, req, res = noopRes()) {
  return new Promise((resolve, reject) => {
    middleware(req, res, (error) => {
      if (error) {
        reject(error);
      } else {
        resolve(req);
      }
    });
  });
}

export function baseSecrets(clock) {
  return {
    clock,
    ttlMs: 60_000,
    secrets: [
      { version: 'v1', secret: 'old-secret-key-0123456789abcdef', current: false },
      { version: 'v2', secret: 'new-secret-key-abcdef0123456789', current: true }
    ]
  };
}
