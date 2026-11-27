package io.github.aachar0.loganalyzer.parse;

import io.github.aachar0.loganalyzer.geo.IpParser;
import io.github.aachar0.loganalyzer.model.LogEntry;
import io.github.aachar0.loganalyzer.model.Malformed;
import io.github.aachar0.loganalyzer.model.ParseResult;

import java.nio.charset.StandardCharsets;
import java.time.DateTimeException;
import java.time.LocalDate;
import java.util.HashMap;
import java.util.Map;

/**
 * Turns one log line (raw bytes) into a {@link ParseResult}.
 *
 * Expected format (Apache "common log format" plus the response time at the end):
 * <pre>
 * 192.0.2.7 - - [01/Nov/2026:10:15:32 +0000] "GET /api/products/42?size=20 HTTP/1.1" 200 1532 18
 * ip        id user [timestamp, fixed width ]  "METHOD path PROTOCOL"                status bytes ms
 * </pre>
 *
 * Why bytes and not Strings? Reading a line as a String allocates memory for every line. Working on the
 * bytes directly is several times faster, and with millions of lines that matters.
 *
 * The client address is read into numbers (no String is created) so the country can be looked up while counting.
 * The address itself is never stored, and text that is not an address (a host name, "-") does not make a line
 * malformed.
 *
 * Thread safety: an instance keeps a small cache and a reusable buffer, so it is NOT thread-safe.
 * Every worker creates its own parser (cheap), which avoids locks completely.
 */
public final class LogParser {

    private static final int TIMESTAMP_LENGTH = 26;   // dd/MMM/yyyy:HH:mm:ss +ZZZZ
    private static final int MAX_METHOD_LENGTH = 10;
    private static final int MAX_DIGITS = 18;         // a long holds at most 19 digits; stay below

    private final ResponseTimeUnit unit;
    private final Map<Integer, Long> epochDayCache = new HashMap<>();   // yyyymmdd -> days since 1970
    private final StringBuilder routeBuilder = new StringBuilder(64);
    private final IpParser ipParser = new IpParser();

    public LogParser(ResponseTimeUnit unit) {
        this.unit = unit;
    }

    public LogParser() {
        this(ResponseTimeUnit.MILLIS);
    }

    /** Convenience for tests and small tools: parse a String line. */
    public ParseResult parse(String line) {
        byte[] bytes = line.getBytes(StandardCharsets.ISO_8859_1);
        return parse(bytes, 0, bytes.length);
    }

    /** Parses bytes b[off .. off+len). Never throws for bad input: returns Malformed instead. */
    public ParseResult parse(byte[] b, int off, int len) {
        int end = off + len;
        int i = off;

        // 1) Skip the three leading words: client address, identity, user. The first word is the client address:
        //    remember where it ends so it can be read once the whole line is known to be good.
        int ipEnd = off;
        for (int word = 0; word < 3; word++) {
            while (i < end && b[i] != ' ') {
                i++;
            }
            if (i >= end) {
                return Malformed.INSTANCE;
            }
            if (word == 0) {
                ipEnd = i;
            }
            i++;                                           // step over the space
        }

        // 2) Timestamp in square brackets: [dd/MMM/yyyy:HH:mm:ss +ZZZZ]
        if (i + TIMESTAMP_LENGTH + 2 > end || b[i] != '[' || b[i + TIMESTAMP_LENGTH + 1] != ']') {
            return Malformed.INSTANCE;
        }
        long epochMinute = parseTimestamp(b, i + 1);
        if (epochMinute < 0) {
            return Malformed.INSTANCE;
        }
        i += TIMESTAMP_LENGTH + 2;                         // past the closing bracket

        // 3) The quoted request: "METHOD path PROTOCOL"
        if (i + 1 >= end || b[i] != ' ' || b[i + 1] != '"') {
            return Malformed.INSTANCE;
        }
        i += 2;
        int methodStart = i;
        while (i < end && b[i] != ' ') {
            i++;
        }
        int methodLength = i - methodStart;
        if (i >= end || methodLength == 0 || methodLength > MAX_METHOD_LENGTH || !isUpperCase(b, methodStart, i)) {
            return Malformed.INSTANCE;
        }
        String method = new String(b, methodStart, methodLength, StandardCharsets.ISO_8859_1);
        i++;                                               // skip space
        int pathStart = i;
        while (i < end && b[i] != ' ') {
            i++;
        }
        if (i >= end || i == pathStart || b[pathStart] != '/') {
            return Malformed.INSTANCE;
        }
        int pathEnd = i;
        i++;                                               // skip space
        while (i < end && b[i] != '"') {                   // skip the protocol, e.g. HTTP/1.1
            i++;
        }
        if (i >= end) {
            return Malformed.INSTANCE;
        }
        i++;                                               // skip closing quote

        // 4) status, bytes, response time: three numbers separated by single spaces
        if (i >= end || b[i] != ' ') {
            return Malformed.INSTANCE;
        }
        i++;
        if (i + 3 >= end) {
            return Malformed.INSTANCE;
        }
        int d1 = digit(b[i]), d2 = digit(b[i + 1]), d3 = digit(b[i + 2]);
        if ((d1 | d2 | d3) < 0 || b[i + 3] != ' ') {
            return Malformed.INSTANCE;
        }
        int status = d1 * 100 + d2 * 10 + d3;
        if (status < 100 || status > 599) {
            return Malformed.INSTANCE;
        }
        i += 4;

        long bytes;
        if (i < end && b[i] == '-') {                      // "-" means "no body"
            bytes = 0;
            i++;
        } else {
            int bytesStart = i;
            bytes = 0;
            while (i < end && b[i] >= '0' && b[i] <= '9' && i - bytesStart < MAX_DIGITS) {
                bytes = bytes * 10 + (b[i] - '0');
                i++;
            }
            if (i == bytesStart) {
                return Malformed.INSTANCE;
            }
        }
        if (i >= end || b[i] != ' ') {
            return Malformed.INSTANCE;
        }
        i++;

        int timeStart = i;
        long logged = 0;
        while (i < end && b[i] >= '0' && b[i] <= '9' && i - timeStart < MAX_DIGITS) {
            logged = logged * 10 + (b[i] - '0');
            i++;
        }
        if (i == timeStart || i != end) {                  // must be digits up to the end of the line
            return Malformed.INSTANCE;
        }
        long millis = unit.toMillis(logged);
        if (millis > Integer.MAX_VALUE) {
            millis = Integer.MAX_VALUE;
        }

        String route = normaliseRoute(b, pathStart, pathEnd);
        // Only login requests need the client address (to find the country), so the other ~95% of lines skip this work.
        int ipFamily = IpParser.NONE;
        if (methodLength == 4 && b[methodStart] == 'P' && b[methodStart + 1] == 'O' && b[methodStart + 2] == 'S'
                && b[methodStart + 3] == 'T' && isLoginPath(b, pathStart, pathEnd)) {
            ipFamily = ipParser.parse(b, off, ipEnd);       // stays 0 when the first word is not an IP address
        }
        return new LogEntry(epochMinute, method, route, status, bytes, (int) millis,
                ipFamily, ipFamily == IpParser.NONE ? 0L : ipParser.value());
    }

    /**
     * True when the path (query string ignored, one trailing slash tolerated) ends in "login" or "signin" in any
     * letter case. Must agree with LogStats.isLoginAttempt, which decides on the finished route; a test checks this.
     */
    static boolean isLoginPath(byte[] b, int start, int end) {
        for (int k = start; k < end; k++) {
            if (b[k] == '?') {
                end = k;
                break;
            }
        }
        if (end - start > 1 && b[end - 1] == '/') {
            end--;
        }
        int slash = end - 1;
        while (slash >= start && b[slash] != '/') {
            slash--;
        }
        int length = end - slash - 1;
        return (length == 5 && matches(b, slash + 1, "login")) || (length == 6 && matches(b, slash + 1, "signin"));
    }

    private static boolean matches(byte[] b, int from, String word) {
        for (int k = 0; k < word.length(); k++) {
            if ((b[from + k] | 0x20) != word.charAt(k)) {            // | 0x20 makes ASCII letters lower case
                return false;
            }
        }
        return true;
    }

    /**
     * Cuts the query string and replaces all-digit path segments with {id}, so that
     * /api/products/17 and /api/products/18 are counted as ONE route: /api/products/{id}.
     */
    private String normaliseRoute(byte[] b, int start, int end) {
        for (int k = start; k < end; k++) {                // stop at '?': the query string is not part of the route
            if (b[k] == '?') {
                end = k;
                break;
            }
        }
        StringBuilder sb = routeBuilder;
        sb.setLength(0);
        int segmentStart = start;
        for (int k = start; k <= end; k++) {
            if (k == end || b[k] == '/') {
                int segmentLength = k - segmentStart;
                if (segmentLength > 0 && allDigits(b, segmentStart, k)) {
                    sb.append("{id}");
                } else {
                    for (int m = segmentStart; m < k; m++) {
                        sb.append((char) (b[m] & 0xFF));
                    }
                }
                if (k < end) {
                    sb.append('/');
                }
                segmentStart = k + 1;
            }
        }
        return sb.toString();
    }

    /** Returns minutes since 1970 (UTC), or -1 when the timestamp is invalid. */
    private long parseTimestamp(byte[] b, int t) {
        int day = twoDigits(b, t);
        int month = monthNumber(b[t + 3], b[t + 4], b[t + 5]);
        int year = fourDigits(b, t + 7);
        int hour = twoDigits(b, t + 12);
        int minute = twoDigits(b, t + 15);
        int second = twoDigits(b, t + 18);
        int zoneHours = twoDigits(b, t + 22);
        int zoneMinutes = twoDigits(b, t + 24);
        boolean punctuationOk = b[t + 2] == '/' && b[t + 6] == '/' && b[t + 11] == ':' && b[t + 14] == ':'
                && b[t + 17] == ':' && b[t + 20] == ' ' && (b[t + 21] == '+' || b[t + 21] == '-');
        if (!punctuationOk || (day | month | year | hour | minute | second | zoneHours | zoneMinutes) < 0
                || hour > 23 || minute > 59 || second > 60 || zoneHours > 14 || zoneMinutes > 59) {
            return -1;
        }
        long epochDay;
        try {
            int key = year * 10_000 + month * 100 + day;
            Long cached = epochDayCache.get(key);
            if (cached == null) {
                cached = LocalDate.of(year, month, day).toEpochDay();   // throws for 31 Feb and similar
                epochDayCache.put(key, cached);
            }
            epochDay = cached;
        } catch (DateTimeException e) {
            return -1;
        }
        int offsetSeconds = (zoneHours * 3600 + zoneMinutes * 60) * (b[t + 21] == '-' ? -1 : 1);
        long epochSecond = epochDay * 86_400L + hour * 3600L + minute * 60L + second - offsetSeconds;
        return epochSecond < 0 ? -1 : epochSecond / 60;
    }

    private static int monthNumber(byte a, byte b, byte c) {
        return switch ("" + (char) a + (char) b + (char) c) {
            case "Jan" -> 1;
            case "Feb" -> 2;
            case "Mar" -> 3;
            case "Apr" -> 4;
            case "May" -> 5;
            case "Jun" -> 6;
            case "Jul" -> 7;
            case "Aug" -> 8;
            case "Sep" -> 9;
            case "Oct" -> 10;
            case "Nov" -> 11;
            case "Dec" -> 12;
            default -> -1;
        };
    }

    private static int digit(byte c) {
        return c >= '0' && c <= '9' ? c - '0' : -1;
    }

    private static int twoDigits(byte[] b, int p) {
        int x = digit(b[p]), y = digit(b[p + 1]);
        return (x | y) < 0 ? -1 : x * 10 + y;
    }

    private static int fourDigits(byte[] b, int p) {
        int x = twoDigits(b, p), y = twoDigits(b, p + 2);
        return (x | y) < 0 ? -1 : x * 100 + y;
    }

    private static boolean allDigits(byte[] b, int from, int to) {
        for (int k = from; k < to; k++) {
            if (b[k] < '0' || b[k] > '9') {
                return false;
            }
        }
        return true;
    }

    private static boolean isUpperCase(byte[] b, int from, int to) {
        for (int k = from; k < to; k++) {
            if (b[k] < 'A' || b[k] > 'Z') {
                return false;
            }
        }
        return true;
    }
}
