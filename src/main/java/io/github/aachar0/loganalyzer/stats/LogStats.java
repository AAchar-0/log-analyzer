package io.github.aachar0.loganalyzer.stats;

import io.github.aachar0.loganalyzer.model.LogEntry;
import io.github.aachar0.loganalyzer.model.Malformed;
import io.github.aachar0.loganalyzer.model.ParseResult;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Everything we count while reading a log. One LogStats belongs to ONE worker at a time, so it needs no
 * locks. When workers finish, their LogStats are combined with {@link #merge(LogStats)}.
 *
 * This "give every worker its own counters, merge at the end" idea is the most important pattern in
 * the project: it avoids the slow shared-lock traffic that makes naive parallel code slower than
 * sequential code.
 *
 * Memory use grows with the number of DISTINCT minutes, DISTINCT routes and DISTINCT places that tried to log in,
 * not with the number of lines.
 */
public final class LogStats {

    private long requests;
    private long malformed;
    private long totalBytes;
    private long firstMinute = Long.MAX_VALUE;
    private long lastMinute = Long.MIN_VALUE;
    private final long[] statusCounts = new long[600];                 // index = status code
    private final LatencyHistogram latency = new LatencyHistogram();
    private final Map<Long, long[]> minutes = new HashMap<>();        // minute -> {requests, serverErrors}
    private final Map<String, RouteStats> routes = new HashMap<>();   // "GET /api/x/{id}" -> totals
    private final GeoCounts geo = new GeoCounts();                    // login attempts per place (never per address)

    /** Counts one parsed line. The switch must cover both kinds of ParseResult (the type is sealed). */
    public void accept(ParseResult result) {
        switch (result) {
            case LogEntry entry -> add(entry);
            case Malformed ignored -> malformed++;
        }
    }

    private void add(LogEntry e) {
        requests++;
        totalBytes += e.bytes();
        statusCounts[e.status()]++;
        latency.record(e.millis());
        firstMinute = Math.min(firstMinute, e.epochMinute());
        lastMinute = Math.max(lastMinute, e.epochMinute());

        long[] minute = minutes.computeIfAbsent(e.epochMinute(), k -> new long[2]);
        minute[0]++;
        if (e.isServerError()) {
            minute[1]++;
        }
        routes.computeIfAbsent(e.method() + " " + e.route(), k -> new RouteStats())
                .add(e.millis(), e.isServerError());
        if (isLoginAttempt(e)) {
            geo.recordLogin(e);
        }
    }

    /**
     * A login attempt is a POST to a route whose last part is "login" or "signin", for example /api/auth/login.
     * Getting the page itself (GET /login) is not an attempt.
     */
    static boolean isLoginAttempt(LogEntry e) {
        if (!"POST".equals(e.method())) {
            return false;
        }
        String route = e.route();
        int end = route.length();
        if (end > 1 && route.charAt(end - 1) == '/') {
            end--;                                                 // tolerate /api/auth/login/
        }
        int slash = route.lastIndexOf('/', end - 1);
        int length = end - slash - 1;
        return (length == 5 && route.regionMatches(true, slash + 1, "login", 0, 5))
                || (length == 6 && route.regionMatches(true, slash + 1, "signin", 0, 6));
    }

    /** Adds everything counted by another LogStats into this one. */
    public void merge(LogStats other) {
        requests += other.requests;
        malformed += other.malformed;
        totalBytes += other.totalBytes;
        firstMinute = Math.min(firstMinute, other.firstMinute);
        lastMinute = Math.max(lastMinute, other.lastMinute);
        for (int i = 0; i < statusCounts.length; i++) {
            statusCounts[i] += other.statusCounts[i];
        }
        latency.merge(other.latency);
        other.minutes.forEach((minute, counts) -> {
            long[] mine = minutes.computeIfAbsent(minute, k -> new long[2]);
            mine[0] += counts[0];
            mine[1] += counts[1];
        });
        other.routes.forEach((route, stats) ->
                routes.computeIfAbsent(route, k -> new RouteStats()).merge(stats));
        geo.merge(other.geo);
    }

    public long requests() {
        return requests;
    }

    public long malformed() {
        return malformed;
    }

    public long totalBytes() {
        return totalBytes;
    }

    public long firstMinute() {
        return requests == 0 ? 0 : firstMinute;
    }

    public long lastMinute() {
        return requests == 0 ? 0 : lastMinute;
    }

    public long statusCount(int status) {
        return statusCounts[status];
    }

    public LatencyHistogram latency() {
        return latency;
    }

    /** Read-only view: minute -> {requests, serverErrors}. */
    public Map<Long, long[]> minutes() {
        return Collections.unmodifiableMap(minutes);
    }

    /** Read-only view: route -> totals. */
    public Map<String, RouteStats> routes() {
        return Collections.unmodifiableMap(routes);
    }

    /** Login attempts per place. */
    public GeoCounts geo() {
        return geo;
    }
}
