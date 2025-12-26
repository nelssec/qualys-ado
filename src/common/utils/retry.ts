export interface RetryConfig {
  maxRetries: number;
  baseDelayMs: number;
  maxDelayMs: number;
  retryableStatuses: number[];
}

export const defaultRetryConfig: RetryConfig = {
  maxRetries: 3,
  baseDelayMs: 1000,
  maxDelayMs: 30000,
  retryableStatuses: [429, 500, 502, 503, 504],
};

export async function withRetry<T>(
  operation: () => Promise<T>,
  config: RetryConfig = defaultRetryConfig,
  onRetry?: (attempt: number, error: Error, delayMs: number) => void
): Promise<T> {
  let lastError: Error | null = null;

  for (let attempt = 0; attempt <= config.maxRetries; attempt++) {
    try {
      return await operation();
    } catch (error: unknown) {
      lastError = error as Error;

      const isRetryable = isRetryableError(error, config.retryableStatuses);
      const isLastAttempt = attempt === config.maxRetries;

      if (!isRetryable || isLastAttempt) {
        throw error;
      }

      const delay = Math.min(config.baseDelayMs * Math.pow(2, attempt), config.maxDelayMs);

      if (onRetry) {
        onRetry(attempt + 1, lastError, delay);
      }

      await sleep(delay);
    }
  }

  throw lastError;
}

function isRetryableError(error: unknown, retryableStatuses: number[]): boolean {
  if (error && typeof error === 'object' && 'response' in error) {
    const status = (error as { response?: { status?: number } }).response?.status;
    return status !== undefined && retryableStatuses.includes(status);
  }
  if (error && typeof error === 'object' && 'code' in error) {
    const code = (error as { code?: string }).code;
    return code === 'ECONNRESET' || code === 'ETIMEDOUT' || code === 'ECONNREFUSED';
  }
  return false;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
