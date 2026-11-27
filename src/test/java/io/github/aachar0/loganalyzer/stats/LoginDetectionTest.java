package io.github.aachar0.loganalyzer.stats;

import io.github.aachar0.loganalyzer.model.LogEntry;
import io.github.aachar0.loganalyzer.parse.LogParser;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The parser decides from raw bytes whether to read the client address; LogStats decides from the finished route
 * whether to count a login. Both rules must always agree, otherwise a login would be counted without an address.
 */
class LoginDetectionTest {

    private static LogEntry parse(String ip, String method, String path) {
        String line = ip + " - - [01/Nov/2026:10:15:32 +0000] \"" + method + " " + path + " HTTP/1.1\" 200 5 1";
        return assertInstanceOf(LogEntry.class, new LogParser().parse(line));
    }

    @Test
    void parserAndStatsAgreeOnWhatALoginIs() {
        String[] logins = {"/login", "/api/auth/login", "/api/auth/login/", "/api/auth/LOGIN", "/api/auth/Login?next=/x",
                "/signin", "/api/v1/SignIn", "/a/b/c/login?x=1&y=2", "/api/products/5/login"};
        String[] notLogins = {"/", "/api/auth/register", "/api/auth/logout", "/api/auth/login-history", "/api/login/history",
                "/api/auth/logins", "/loginx", "/xlogin", "/api/auth/log", "/api/signin/help", "/api/products/{id}".replace("{id}", "7")};
        for (String path : logins) {
            LogEntry e = parse("41.89.198.9", "POST", path);
            assertTrue(LogStats.isLoginAttempt(e), "stats: " + path);
            assertEquals(4, e.ipFamily(), "parser read the address for " + path);
        }
        for (String path : notLogins) {
            LogEntry e = parse("41.89.198.9", "POST", path);
            assertEquals(false, LogStats.isLoginAttempt(e), "stats: " + path);
            assertEquals(0, e.ipFamily(), "parser skipped the address for " + path);
        }
        for (String method : new String[]{"GET", "PUT", "DELETE", "PATCH", "POSTS", "POS"}) {
            LogEntry e = parse("41.89.198.9", method, "/api/auth/login");
            assertEquals(false, LogStats.isLoginAttempt(e), method);
            assertEquals(0, e.ipFamily(), method);
        }
    }

    @Test
    void aLoginWithAnUnreadableAddressIsStillAValidLine() {
        for (String ip : new String[]{"-", "localhost", "999.1.1.1", "unknown"}) {
            LogEntry e = parse(ip, "POST", "/api/auth/login");
            assertEquals(0, e.ipFamily(), ip);
            assertTrue(LogStats.isLoginAttempt(e), ip);
        }
    }

    @Test
    void ipv6AndMappedAddressesAreRead() {
        assertEquals(6, parse("2a02:d107:e000::1", "POST", "/login").ipFamily());
        LogEntry mapped = parse("::ffff:41.89.198.9", "POST", "/login");
        assertEquals(4, mapped.ipFamily());
        assertEquals((41L << 24) | (89L << 16) | (198L << 8) | 9, mapped.ip());
    }
}
