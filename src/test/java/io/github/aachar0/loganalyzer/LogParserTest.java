package io.github.aachar0.loganalyzer;

import io.github.aachar0.loganalyzer.model.LogEntry;
import io.github.aachar0.loganalyzer.model.Malformed;
import io.github.aachar0.loganalyzer.model.ParseResult;
import io.github.aachar0.loganalyzer.parse.LogParser;
import io.github.aachar0.loganalyzer.parse.ResponseTimeUnit;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LogParserTest {

    private static final String GOOD =
            "192.0.2.7 - - [01/Nov/2026:10:15:32 +0000] \"GET /api/products/42?size=20 HTTP/1.1\" 200 1532 18";

    private static long minuteOf(String isoInstant) {
        return Instant.parse(isoInstant).getEpochSecond() / 60;
    }

    @Test
    void parsesAGoodLine() {
        LogEntry e = assertInstanceOf(LogEntry.class, new LogParser().parse(GOOD));
        assertEquals("GET", e.method());
        assertEquals("/api/products/{id}", e.route());     // query cut, number replaced
        assertEquals(200, e.status());
        assertEquals(1532L, e.bytes());
        assertEquals(18, e.millis());
        assertEquals(minuteOf("2026-11-01T10:15:00Z"), e.epochMinute());
    }

    @Test
    void dashMeansZeroBytes() {
        LogEntry e = assertInstanceOf(LogEntry.class, new LogParser().parse(
                "192.0.2.7 - user1 [01/Nov/2026:10:15:32 +0000] \"DELETE /api/products/5 HTTP/1.1\" 204 - 12"));
        assertEquals(0L, e.bytes());
        assertEquals(204, e.status());
    }

    @Test
    void timezoneOffsetIsConvertedToUtc() {
        LogEntry plus = assertInstanceOf(LogEntry.class, new LogParser().parse(
                "192.0.2.7 - - [01/Nov/2026:10:15:32 +0300] \"GET / HTTP/1.1\" 200 5 1"));
        assertEquals(minuteOf("2026-11-01T07:15:00Z"), plus.epochMinute());
        LogEntry minus = assertInstanceOf(LogEntry.class, new LogParser().parse(
                "192.0.2.7 - - [01/Nov/2026:23:30:00 -0500] \"GET / HTTP/1.1\" 200 5 1"));
        assertEquals(minuteOf("2026-11-02T04:30:00Z"), minus.epochMinute());
    }

    @Test
    void microsecondsAreConvertedToMilliseconds() {
        ParseResult r = new LogParser(ResponseTimeUnit.MICROS).parse(
                "192.0.2.7 - - [01/Nov/2026:10:15:32 +0000] \"GET / HTTP/1.1\" 200 5 18000");
        assertEquals(18, assertInstanceOf(LogEntry.class, r).millis());
    }

    @Test
    void routesAreNormalised() {
        LogParser parser = new LogParser();
        assertEquals("/api/products/{id}/movements", route(parser, "/api/products/12/movements"));
        assertEquals("/api/v2/items", route(parser, "/api/v2/items"));
        assertEquals("/", route(parser, "/"));
        assertEquals("/api/products/12abc", route(parser, "/api/products/12abc"));   // not all digits: kept
        assertEquals("/api/products/low-stock", route(parser, "/api/products/low-stock?x=1&y=2"));
    }

    private static String route(LogParser parser, String path) {
        String line = "192.0.2.7 - - [01/Nov/2026:10:15:32 +0000] \"GET " + path + " HTTP/1.1\" 200 5 1";
        return assertInstanceOf(LogEntry.class, parser.parse(line)).route();
    }

    @Test
    void badLinesAreMalformedAndNeverThrow() {
        List<String> bad = List.of(
                "",
                "garbage",
                "192.0.2.7 - -",
                "192.0.2.7 - - [01/Nov/2026:10:15:32 +0000] GET /x HTTP/1.1 200 5 1",                  // no quotes
                "192.0.2.7 - - [01/Foo/2026:10:15:32 +0000] \"GET /x HTTP/1.1\" 200 5 1",              // bad month
                "192.0.2.7 - - [31/Feb/2026:10:15:32 +0000] \"GET /x HTTP/1.1\" 200 5 1",              // no such day
                "192.0.2.7 - - [01/Nov/2026:25:15:32 +0000] \"GET /x HTTP/1.1\" 200 5 1",              // hour 25
                "192.0.2.7 - - [01/Nov/2026:10:15:32 +0000] \"GET /x HTTP/1.1\" 099 5 1",              // status < 100
                "192.0.2.7 - - [01/Nov/2026:10:15:32 +0000] \"GET /x HTTP/1.1\" 200 abc 1",            // bytes not a number
                "192.0.2.7 - - [01/Nov/2026:10:15:32 +0000] \"GET /x HTTP/1.1\" 200 5 1 extra",        // trailing junk
                "192.0.2.7 - - [01/Nov/2026:10:15:32 +0000] \"GET /x HTTP/1.1\" 200 5",                // no time
                "192.0.2.7 - - [01/Nov/2026:10:15:32 +0000] \"get /x HTTP/1.1\" 200 5 1",              // lower-case method
                "192.0.2.7 - - [01/Nov/2026:10:15:32 +0000] \"GET x HTTP/1.1\" 200 5 1",               // path without slash
                "192.0.2.7 - - [01/Nov/2026:10:15:32 +0000 \"GET /x HTTP/1.1\" 200 5 1");              // bracket missing
        LogParser parser = new LogParser();
        for (String line : bad) {
            assertTrue(parser.parse(line) instanceof Malformed, "should be malformed: " + line);
        }
    }

    @Test
    void goodLineStillParsesAfterBadOnes() {
        LogParser parser = new LogParser();
        parser.parse("garbage");
        assertInstanceOf(LogEntry.class, parser.parse(GOOD));
    }
}
