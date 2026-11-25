package io.github.aachar0.loganalyzer.gen;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.SplittableRandom;

/**
 * Writes realistic, SYNTHETIC web-server logs for an inventory-style API (the routes match the Inventory API
 * project). Nothing here comes from real users, so there is no personal data and no licence question.
 *
 * Reproducible: the same seed always produces the byte-identical file, so benchmarks and tests can be repeated.
 *
 * What makes the data realistic enough to be interesting:
 *  - traffic follows a day curve (quiet at night, busy in working hours);
 *  - every route has its own typical speed (login is slow because passwords are hashed on purpose);
 *  - response times are skewed: most are fast, a few are very slow;
 *  - one short "incident" is planted in each file: many 5xx errors and slow answers for a few minutes,
 *    so the report has a real story to find.
 *
 * Client addresses come from the ranges reserved for documentation (RFC 5737), which never belong to a person.
 */
public final class LogGenerator {

    /** Fixed start so the same seed gives the same file: 1 November 2026, 00:00 UTC. */
    public static final long START_EPOCH_MILLIS = Instant.parse("2026-11-01T00:00:00Z").toEpochMilli();

    private static final String[] ADDRESS_PREFIXES = {"192.0.2.", "198.51.100.", "203.0.113."};
    private static final DateTimeFormatter STAMP =
            DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH).withZone(ZoneOffset.UTC);

    /** One kind of request. "{id}" in the pattern is replaced by a random product number. */
    private record RouteSpec(String method, String pattern, int weight, double medianMs, int averageBytes,
                             int[] statuses, int[] statusWeights) {
    }

    private static final RouteSpec[] ROUTES = {
            new RouteSpec("GET", "/api/products", 30, 22, 4200, new int[]{200, 401}, new int[]{985, 15}),
            new RouteSpec("GET", "/api/products/{id}", 28, 9, 520, new int[]{200, 404, 401}, new int[]{940, 45, 15}),
            new RouteSpec("GET", "/api/products/low-stock", 6, 35, 1800, new int[]{200, 401}, new int[]{990, 10}),
            new RouteSpec("GET", "/api/categories", 10, 6, 900, new int[]{200, 401}, new int[]{990, 10}),
            new RouteSpec("GET", "/api/products/{id}/movements", 7, 18, 2100, new int[]{200, 404}, new int[]{970, 30}),
            new RouteSpec("POST", "/api/products/{id}/movements", 9, 24, 380, new int[]{201, 409, 404, 400}, new int[]{900, 60, 20, 20}),
            new RouteSpec("POST", "/api/auth/login", 5, 140, 610, new int[]{200, 401}, new int[]{930, 70}),
            new RouteSpec("POST", "/api/auth/register", 1, 150, 540, new int[]{201, 400, 409}, new int[]{900, 60, 40}),
            new RouteSpec("POST", "/api/products", 2, 30, 640, new int[]{201, 400, 403}, new int[]{930, 40, 30}),
            new RouteSpec("PUT", "/api/products/{id}", 2, 28, 640, new int[]{200, 404, 403}, new int[]{930, 40, 30}),
            new RouteSpec("DELETE", "/api/products/{id}", 1, 20, 0, new int[]{204, 404, 403}, new int[]{920, 50, 30}),
    };
    private static final int TOTAL_WEIGHT = java.util.Arrays.stream(ROUTES).mapToInt(RouteSpec::weight).sum();

    private LogGenerator() {
    }

    /**
     * Writes exactly {@code lines} log lines to {@code out} and returns the file size in bytes.
     * Memory use is tiny and constant: lines are written through a buffer, never kept in a list.
     */
    public static long generate(Path out, long lines, long seed) throws IOException {
        if (lines < 0) {
            throw new IllegalArgumentException("lines must not be negative");
        }
        SplittableRandom random = new SplittableRandom(seed);
        double baseGapMillis = 25.0;
        double expectedSpan = lines * baseGapMillis / 0.62;          // rough length of the log in milliseconds
        long incidentStart = START_EPOCH_MILLIS + (long) (expectedSpan * (0.25 + 0.5 * random.nextDouble()));
        long incidentEnd = incidentStart + 4 * 60_000L;               // four minutes

        long time = START_EPOCH_MILLIS;
        long lastSecond = Long.MIN_VALUE;
        String stamp = "";
        StringBuilder line = new StringBuilder(160);

        try (BufferedWriter writer = new BufferedWriter(
                new OutputStreamWriter(Files.newOutputStream(out), StandardCharsets.US_ASCII), 1 << 20)) {
            for (long n = 0; n < lines; n++) {
                // Time moves forward by a random gap; the gap is shorter when the "day curve" is high.
                double hour = ((time - START_EPOCH_MILLIS) / 3_600_000.0) % 24.0;
                double load = 0.25 + 0.75 * Math.max(0.0, StrictMath.sin(Math.PI * (hour - 6.0) / 16.0));
                double gap = -StrictMath.log(1.0 - random.nextDouble()) * baseGapMillis / load;
                time += Math.max(1L, (long) gap);
                boolean incident = time >= incidentStart && time < incidentEnd;

                long second = time / 1000;
                if (second != lastSecond) {                           // format the timestamp once per second only
                    stamp = STAMP.format(Instant.ofEpochMilli(time));
                    lastSecond = second;
                }

                RouteSpec route = pickRoute(random);
                int status = pickStatus(random, route);
                boolean backend = route.pattern().startsWith("/api/products");
                if (incident && backend && random.nextInt(100) < 30) {
                    status = random.nextInt(100) < 70 ? 500 : 503;    // the planted outage
                }
                long millis = responseTime(random, route.medianMs(), incident ? 6.0 : 1.0, status >= 500);
                int bytes = status == 204 ? 0 : (int) (route.averageBytes() * (0.5 + random.nextDouble()));
                if (status >= 400) {
                    bytes = 120 + random.nextInt(200);                // short error body
                }

                line.setLength(0);
                line.append(ADDRESS_PREFIXES[random.nextInt(ADDRESS_PREFIXES.length)])
                        .append(1 + random.nextInt(254))
                        .append(" - ")
                        .append(random.nextInt(100) < 55 ? "-" : "user" + (1 + random.nextInt(80)))
                        .append(" [").append(stamp).append("] \"")
                        .append(route.method()).append(' ').append(path(random, route)).append(" HTTP/1.1\" ")
                        .append(status).append(' ')
                        .append(bytes == 0 ? "-" : String.valueOf(bytes)).append(' ')
                        .append(millis).append('\n');
                writer.append(line);
            }
        }
        return Files.size(out);
    }

    private static RouteSpec pickRoute(SplittableRandom random) {
        int roll = random.nextInt(TOTAL_WEIGHT);
        for (RouteSpec route : ROUTES) {
            roll -= route.weight();
            if (roll < 0) {
                return route;
            }
        }
        return ROUTES[0];
    }

    private static int pickStatus(SplittableRandom random, RouteSpec route) {
        int total = 0;
        for (int w : route.statusWeights()) {
            total += w;
        }
        int roll = random.nextInt(total);
        for (int i = 0; i < route.statuses().length; i++) {
            roll -= route.statusWeights()[i];
            if (roll < 0) {
                return route.statuses()[i];
            }
        }
        return route.statuses()[0];
    }

    /** Fills the {id} placeholder (popular products get more traffic) and sometimes adds paging parameters. */
    private static String path(SplittableRandom random, RouteSpec route) {
        String path = route.pattern();
        if (path.contains("{id}")) {
            double r = random.nextDouble();
            int id = 1 + (int) (500 * r * r * r);                     // r cubed: low numbers are far more common
            path = path.replace("{id}", Integer.toString(id));
        }
        if (route.pattern().equals("/api/products") && route.method().equals("GET") && random.nextInt(100) < 60) {
            path += "?page=" + random.nextInt(20) + "&size=20";
        }
        return path;
    }

    /** Skewed ("log-normal") response time: usually near the median, sometimes much slower. */
    private static long responseTime(SplittableRandom random, double median, double slowdown, boolean failed) {
        double u1 = 1.0 - random.nextDouble();
        double u2 = random.nextDouble();
        double gaussian = StrictMath.sqrt(-2.0 * StrictMath.log(u1)) * StrictMath.cos(2.0 * Math.PI * u2);
        double millis = median * StrictMath.exp(0.45 * gaussian) * slowdown;
        if (random.nextInt(100) == 0) {
            millis *= 5 + random.nextInt(16);                         // 1 in 100 requests is a slow outlier
        }
        if (failed) {
            millis *= 2;
        }
        return Math.max(1L, Math.min(30_000L, Math.round(millis)));
    }
}
