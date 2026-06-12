// MemoryNonceStore 只适合单进程 demo 或测试；生产环境应替换成共享存储。
import type { NonceStore } from "./types.js";

export class MemoryNonceStore implements NonceStore {
  readonly #entries = new Map<string, number>();

  async has(key: string): Promise<boolean> {
    // 每次读写前顺手清理过期项，保持实现简单。
    this.#sweep();
    return this.#entries.has(key);
  }

  async set(key: string, ttlSeconds: number): Promise<void> {
    this.#entries.set(key, Date.now() + ttlSeconds * 1000);
    this.#sweep();
  }

  #sweep(): void {
    const now = Date.now();
    for (const [key, expiresAt] of this.#entries.entries()) {
      if (expiresAt <= now) {
        this.#entries.delete(key);
      }
    }
  }
}
