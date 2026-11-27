export type StopReason = 'OPERATION_BUDGET' | 'TIME_BUDGET' | 'CANCELLED';
export interface BudgetOptions {
  readonly maxOperations?: number;
  readonly timeBudgetMs?: number;
  readonly yieldEvery?: number;
  readonly signal?: AbortSignal;
}
/** Shared across execution phases. Time is a safety net, operations are deterministic. */
export class ExecutionBudget {
  readonly #max: number;
  readonly #deadline: number;
  readonly #yieldEvery: number;
  readonly #signal: AbortSignal | undefined;
  #operations = 0;
  #sinceYield = 0;
  constructor(options: BudgetOptions = {}) {
    this.#max = options.maxOperations ?? 25_000_000;
    const ms = options.timeBudgetMs ?? 5000;
    this.#yieldEvery = options.yieldEvery ?? 4096;
    if (
      !Number.isSafeInteger(this.#max) ||
      this.#max < 0 ||
      !Number.isFinite(ms) ||
      ms < 0 ||
      !Number.isSafeInteger(this.#yieldEvery) ||
      this.#yieldEvery < 1
    )
      throw new RangeError('Invalid execution budget');
    this.#deadline = performance.now() + ms;
    this.#signal = options.signal;
  }
  get operations() {
    return this.#operations;
  }
  get remainingOperations() {
    return this.#max - this.#operations;
  }
  get stopReason(): StopReason | undefined {
    if (this.#signal?.aborted) return 'CANCELLED';
    if (this.#operations >= this.#max) return 'OPERATION_BUDGET';
    if (performance.now() >= this.#deadline) return 'TIME_BUDGET';
    return undefined;
  }
  /** Caller checks stopReason before doing work. */
  charge(count = 1): void {
    if (!Number.isSafeInteger(count) || count < 0 || count > this.remainingOperations)
      throw new RangeError('Operation budget exceeded');
    this.#operations += count;
    this.#sinceYield += count;
  }
  get operationsUntilYield() {
    return Math.max(0, this.#yieldEvery - this.#sinceYield);
  }
  get shouldYield() {
    return this.#sinceYield >= this.#yieldEvery;
  }
  async yieldControl(): Promise<void> {
    this.#sinceYield = 0;
    // A macrotask, not a resolved promise: allows IO and cancellation events.
    await new Promise<void>((resolve) => {
      const immediate = (
        globalThis as typeof globalThis & { setImmediate?: (callback: () => void) => unknown }
      ).setImmediate;
      if (immediate) immediate(resolve);
      else setTimeout(resolve, 0);
    });
  }
}
