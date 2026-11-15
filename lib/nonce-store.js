export class MemoryNonceStore {
  #nonces = new Map();
  #sweepThreshold;
  #clock;

  constructor({ sweepThreshold = 1000, clock = () => Date.now() } = {}) {
    this.#sweepThreshold = sweepThreshold;
    this.#clock = clock;
  }

  get size() {
    return this.#nonces.size;
  }

  async consume(jti, expiresAtMs) {
    if (this.#nonces.has(jti)) {
      return false;
    }
    this.#nonces.set(jti, expiresAtMs);
    if (this.#nonces.size >= this.#sweepThreshold) {
      this.sweep();
    }
    return true;
  }

  sweep(now = this.#clock()) {
    for (const [jti, expiresAt] of this.#nonces) {
      if (expiresAt <= now) {
        this.#nonces.delete(jti);
      }
    }
    return this.#nonces.size;
  }

  clear() {
    this.#nonces.clear();
  }
}
