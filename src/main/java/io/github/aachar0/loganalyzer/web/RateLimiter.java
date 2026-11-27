package io.github.aachar0.loganalyzer.web;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Allows each client a fixed number of expensive requests per minute (fixed one-minute windows).
 *
 * The analysis slot already stops two analyses from running at once, but it does nothing about one client
 * uploading file after file or asking again and again. This puts a ceiling on that. Memory is bounded: when the
 * table holds too many clients, windows that have already ended are dropped.
 */
final class RateLimiter {

    private static final long WINDOW_NANOS = 60_000_000_000L;
    private static final int MAX_CLIENTS = 10_000;

    private final int limitPerMinute;
    private final ConcurrentHashMap<String, long[]> windows = new ConcurrentHashMap<>();   // {windowStart, count}

    /** @param limitPerMinute requests allowed per client per minute; 0 or less switches the limiter off */
    RateLimiter(int limitPerMinute) {
        this.limitPerMinute = limitPerMinute;
    }

    /** True when this client may go ahead; false when it has used up its minute. */
    boolean tryAcquire(String client) {
        return tryAcquire(client, System.nanoTime());
    }

    boolean tryAcquire(String client, long nowNanos) {
        if (limitPerMinute <= 0) {
            return true;
        }
        if (windows.size() > MAX_CLIENTS) {
            windows.values().removeIf(w -> nowNanos - w[0] >= WINDOW_NANOS);
            if (windows.size() > MAX_CLIENTS) {
                windows.clear();                              // under a flood from many addresses, start over
            }
        }
        long[] window = windows.computeIfAbsent(client, k -> new long[]{nowNanos, 0});
        synchronized (window) {
            if (nowNanos - window[0] >= WINDOW_NANOS) {
                window[0] = nowNanos;
                window[1] = 0;
            }
            if (window[1] >= limitPerMinute) {
                return false;
            }
            window[1]++;
            return true;
        }
    }
}
