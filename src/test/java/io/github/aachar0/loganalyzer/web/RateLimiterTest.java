package io.github.aachar0.loganalyzer.web;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RateLimiterTest {

    private static final long MINUTE = 60_000_000_000L;

    @Test
    void allowsTheLimitThenRefusesUntilTheNextMinute() {
        RateLimiter limiter = new RateLimiter(3);
        for (int i = 0; i < 3; i++) {
            assertTrue(limiter.tryAcquire("a", 1_000L + i));
        }
        assertFalse(limiter.tryAcquire("a", 5_000L));
        assertFalse(limiter.tryAcquire("a", MINUTE - 1));
        assertTrue(limiter.tryAcquire("a", 1_000L + MINUTE), "a new minute starts a new allowance");
    }

    @Test
    void clientsDoNotShareAnAllowance() {
        RateLimiter limiter = new RateLimiter(1);
        assertTrue(limiter.tryAcquire("a", 1));
        assertFalse(limiter.tryAcquire("a", 2));
        assertTrue(limiter.tryAcquire("b", 3));
    }

    @Test
    void zeroSwitchesTheLimiterOff() {
        RateLimiter limiter = new RateLimiter(0);
        for (int i = 0; i < 1000; i++) {
            assertTrue(limiter.tryAcquire("a", i));
        }
    }

    @Test
    void theTableStaysBoundedUnderAFloodOfDifferentClients() {
        RateLimiter limiter = new RateLimiter(5);
        for (int i = 0; i < 30_000; i++) {
            assertTrue(limiter.tryAcquire("client-" + i, i));
        }
        assertTrue(limiter.tryAcquire("late", 31_000));
    }
}
