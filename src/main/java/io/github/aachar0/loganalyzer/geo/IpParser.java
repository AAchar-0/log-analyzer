package io.github.aachar0.loganalyzer.geo;

import java.nio.charset.StandardCharsets;

/**
 * Reads an IP address written as text (IPv4 or IPv6) straight from log bytes WITHOUT creating any objects.
 * Creating a String for every line would slow down big files, so the parser keeps its result in two fields
 * ({@link #family()} and {@link #value()}) and reuses a small scratch array.
 *
 * What "value" means:
 * <ul>
 *   <li>IPv4: the address as a number from 0 to 4,294,967,295 (for example 41.89.0.1).</li>
 *   <li>IPv6: the FIRST 64 BITS of the address. Providers never split their ranges finer than that, so the
 *       first 64 bits are enough to find the country and city, and they fit in one long.</li>
 *   <li>An IPv6 address that is really an IPv4 address in disguise (::ffff:1.2.3.4) is returned as IPv4.</li>
 * </ul>
 *
 * Text that is not an address (a host name, "-", "unknown", junk) gives family {@link #NONE}. That never makes a
 * log line malformed: the rest of the line is still counted exactly as before.
 *
 * Thread safety: NOT thread-safe, on purpose (no locks). Every worker owns its own parser through its LogParser.
 */
public final class IpParser {

    public static final int NONE = 0;
    public static final int V4 = 4;
    public static final int V6 = 6;

    private final int[] groups = new int[8];
    private int family;
    private long value;

    /** What the last call to parse() found: NONE, V4 or V6. */
    public int family() {
        return family;
    }

    /** The IPv4 number, or the first 64 bits of an IPv6 address. Only meaningful when family() is not NONE. */
    public long value() {
        return value;
    }

    /** Convenience for tests and tools. Returns the family. */
    public int parse(String text) {
        byte[] bytes = text.getBytes(StandardCharsets.ISO_8859_1);
        return parse(bytes, 0, bytes.length);
    }

    /** Parses b[from .. to). Never throws; returns NONE for anything that is not an IP address. */
    public int parse(byte[] b, int from, int to) {
        family = NONE;
        value = 0;
        int length = to - from;
        if (length < 2 || length > 45) {                      // "::" is the shortest IPv6 text, 45 chars the longest
            return NONE;
        }
        for (int i = from; i < to; i++) {
            if (b[i] == ':') {
                return parseV6(b, from, to);
            }
        }
        if (length < 7) {                                     // the shortest IPv4 text, 0.0.0.0, has 7 characters
            return NONE;
        }
        long v4 = parseV4(b, from, to);
        if (v4 < 0) {
            return NONE;
        }
        value = v4;
        family = V4;
        return V4;
    }

    /** Returns the address as 0..4294967295, or -1 when b[from..to) is not exactly "a.b.c.d". */
    private static long parseV4(byte[] b, int from, int to) {
        long result = 0;
        int octets = 0;
        int i = from;
        while (true) {
            int start = i;
            int octet = 0;
            while (i < to && b[i] >= '0' && b[i] <= '9') {
                octet = octet * 10 + (b[i] - '0');
                if (octet > 255 || i - start >= 3) {
                    return -1;
                }
                i++;
            }
            if (i == start) {
                return -1;                                    // empty octet such as "1..2.3"
            }
            result = (result << 8) | octet;
            octets++;
            if (i == to) {
                return octets == 4 ? result : -1;
            }
            if (b[i] != '.' || octets == 4) {
                return -1;
            }
            i++;
        }
    }

    private int parseV6(byte[] b, int from, int to) {
        int[] g = groups;
        int n = 0;                                            // groups read so far
        int compressAt = -1;                                  // position of "::" in the group list
        int i = from;

        if (b[i] == ':') {                                    // an address may start with "::" but not with one ":"
            if (i + 1 >= to || b[i + 1] != ':') {
                return NONE;
            }
            compressAt = 0;
            i += 2;
        }
        while (i < to) {
            int start = i;
            int val = 0;
            int digits = 0;
            int h;
            while (i < to && (h = hex(b[i])) >= 0) {
                val = (val << 4) | h;
                if (++digits > 4) {
                    return NONE;
                }
                i++;
            }
            if (i < to && b[i] == '.') {                      // an IPv4 tail such as ::ffff:1.2.3.4
                long v4 = parseV4(b, start, to);
                if (v4 < 0 || n > 6) {
                    return NONE;
                }
                g[n++] = (int) (v4 >>> 16);
                g[n++] = (int) (v4 & 0xFFFF);
                i = to;
                break;
            }
            if (digits == 0 || n >= 8) {
                return NONE;
            }
            g[n++] = val;
            if (i == to) {
                break;
            }
            if (b[i] != ':') {
                return NONE;                                  // zone ids (%eth0) and other junk are not accepted
            }
            i++;
            if (i < to && b[i] == ':') {                      // a second colon: this is the "::"
                if (compressAt >= 0) {
                    return NONE;                              // only one "::" is allowed
                }
                compressAt = n;
                i++;
            } else if (i == to) {
                return NONE;                                  // a single trailing ":"
            }
        }

        if (compressAt >= 0) {
            if (n > 7) {
                return NONE;
            }
            int tail = n - compressAt;                        // groups after the "::"
            for (int k = 0; k < tail; k++) {
                g[7 - k] = g[n - 1 - k];
            }
            for (int k = compressAt; k < 8 - tail; k++) {
                g[k] = 0;
            }
        } else if (n != 8) {
            return NONE;
        }

        if (g[0] == 0 && g[1] == 0 && g[2] == 0 && g[3] == 0 && g[4] == 0 && g[5] == 0xFFFF) {
            value = ((long) g[6] << 16) | g[7];               // IPv4-mapped: treat as the IPv4 address it carries
            family = V4;
            return V4;
        }
        value = ((long) g[0] << 48) | ((long) g[1] << 32) | ((long) g[2] << 16) | g[3];
        family = V6;
        return V6;
    }

    private static int hex(byte c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        return -1;
    }
}
