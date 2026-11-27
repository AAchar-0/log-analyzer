package io.github.aachar0.loganalyzer.geo;

import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;

class IpParserTest {

    private final IpParser p = new IpParser();

    @Test
    void ipv4IsParsedToANumber() {
        assertEquals(IpParser.V4, p.parse("41.89.198.5"));
        assertEquals((41L << 24) | (89L << 16) | (198L << 8) | 5, p.value());
        assertEquals(IpParser.V4, p.parse("255.255.255.255"));
        assertEquals(0xFFFF_FFFFL, p.value());
        assertEquals(IpParser.V4, p.parse("0.0.0.0"));
        assertEquals(0L, p.value());
    }

    @Test
    void thingsThatAreNotAddressesGiveNone() {
        for (String text : new String[]{"", "-", "unknown", "localhost", "256.1.1.1", "1.2.3", "1.2.3.4.5", "1..2.3",
                "1.2.3.4 ", "a.b.c.d", "1.2.3.1000", "1.2.3.-4", "::g", ":1:2:3:4:5:6:7", "1:2:3:4:5:6:7", "1::2::3",
                "1:2:3:4:5:6:7:8:9", "12345::1", "fe80::1%eth0", "1:2:3:4:5:6:7::8:9", "2001:db8:::1", "2001:db8::1:"}) {
            assertEquals(IpParser.NONE, p.parse(text), "should not be an address: '" + text + "'");
        }
    }

    @Test
    void ipv6TakesTheFirst64Bits() {
        assertEquals(IpParser.V6, p.parse("2001:db8:85a3:1::8a2e:370:7334"));
        assertEquals(0x2001_0db8_85a3_0001L, p.value());
        assertEquals(IpParser.V6, p.parse("2A02:D107:E000:0:EE59:DED9:E48B:E1CF"));          // upper case
        assertEquals(0x2a02_d107_e000_0000L, p.value());
        assertEquals(IpParser.V6, p.parse("2a20::"));                                       // short block starts
        assertEquals(0x2a20_0000_0000_0000L, p.value());
        assertEquals(IpParser.V6, p.parse("2001:db8::"));
        assertEquals(0x2001_0db8_0000_0000L, p.value());
        assertEquals(IpParser.V6, p.parse("1:2:3:4:5:6:7::"));
        assertEquals(0x0001_0002_0003_0004L, p.value());
    }

    @Test
    void ipv4InsideIpv6IsTreatedAsIpv4() {
        assertEquals(IpParser.V4, p.parse("::ffff:41.89.198.5"));
        assertEquals((41L << 24) | (89L << 16) | (198L << 8) | 5, p.value());
        assertEquals(IpParser.V4, p.parse("::ffff:2959:c605"));
        assertEquals((41L << 24) | (89L << 16) | (198L << 8) | 5, p.value());
        assertEquals(IpParser.V6, p.parse("64:ff9b::1.2.3.4"));                          // other IPv4 tails stay IPv6
    }

    /** The JDK's own parser is the referee: 50,000 random addresses must give the same result. */
    @Test
    void agreesWithTheJdkOnRandomAddresses() throws Exception {
        Random random = new Random(11);
        for (int i = 0; i < 25_000; i++) {
            byte[] raw = new byte[4];
            random.nextBytes(raw);
            String text = InetAddress.getByAddress(raw).getHostAddress();
            assertEquals(IpParser.V4, p.parse(text), text);
            assertEquals(((long) (raw[0] & 255) << 24) | ((raw[1] & 255) << 16) | ((raw[2] & 255) << 8) | (raw[3] & 255),
                    p.value(), text);
        }
        for (int i = 0; i < 25_000; i++) {
            byte[] raw = new byte[16];
            random.nextBytes(raw);
            if (random.nextInt(3) == 0) {                      // make runs of zero groups so "::" shows up often
                int from = random.nextInt(8) * 2;
                int to = Math.min(16, from + 2 + random.nextInt(8) * 2);
                for (int k = from; k < to; k++) {
                    raw[k] = 0;
                }
            }
            if (random.nextInt(10) == 0) {
                raw[0] = raw[1] = raw[2] = raw[3] = raw[4] = raw[5] = raw[6] = raw[7] = 0;   // hits the ::1.2.3.4 shapes
            }
            String text = Inet6Text.of(raw);
            long expected = 0;
            for (int k = 0; k < 8; k++) {
                expected = (expected << 8) | (raw[k] & 255);
            }
            int family = p.parse(text);
            boolean mapped = raw[0] == 0 && raw[1] == 0 && raw[2] == 0 && raw[3] == 0 && raw[4] == 0 && raw[5] == 0
                    && raw[6] == 0 && raw[7] == 0 && raw[8] == 0 && raw[9] == 0 && (raw[10] & 255) == 255 && (raw[11] & 255) == 255;
            if (mapped) {
                assertEquals(IpParser.V4, family, text);
            } else {
                assertEquals(IpParser.V6, family, text);
                assertEquals(expected, p.value(), text);
            }
        }
    }

    /** Writes an IPv6 address in the compressed form with "::" (the JDK's getHostAddress never compresses). */
    private static final class Inet6Text {
        static String of(byte[] raw) {
            int[] g = new int[8];
            for (int i = 0; i < 8; i++) {
                g[i] = ((raw[2 * i] & 255) << 8) | (raw[2 * i + 1] & 255);
            }
            int bestStart = -1;
            int bestLen = 0;
            for (int i = 0; i < 8; ) {
                if (g[i] != 0) {
                    i++;
                    continue;
                }
                int j = i;
                while (j < 8 && g[j] == 0) {
                    j++;
                }
                if (j - i > bestLen && j - i >= 2) {
                    bestStart = i;
                    bestLen = j - i;
                }
                i = j;
            }
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 8; i++) {
                if (i == bestStart) {
                    sb.append("::");
                    i += bestLen - 1;
                    continue;
                }
                if (sb.length() > 0 && sb.charAt(sb.length() - 1) != ':') {
                    sb.append(':');
                }
                sb.append(Integer.toHexString(g[i]));
            }
            return sb.toString();
        }
    }
}
