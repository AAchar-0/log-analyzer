package io.github.aachar0.loganalyzer.report;

import io.github.aachar0.loganalyzer.stats.LogStats;
import io.github.aachar0.loganalyzer.stats.RouteStats;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

/**
 * The finished, read-only answer. Because it is made only of records, "report1.equals(report2)" compares
 * every number, which is how the tests prove that all three strategies give identical results.
 */
public record Report(
        long requests,
        long malformedLines,
        long totalBytes,
        long firstMinute,
        long lastMinute,
        long clientErrors,
        long serverErrors,
        Latency latency,
        List<StatusCount> statuses,
        List<MinuteCount> busiestMinutes,
        List<MinuteCount> worstErrorMinutes,
        List<RouteSummary> topRoutes,
        List<RouteSummary> slowestRoutes) {

    public record Latency(double averageMs, long p50, long p90, long p95, long p99, long maxMs) {
    }

    public record StatusCount(int status, long count) {
    }

    public record MinuteCount(long epochMinute, long requests, long serverErrors) {
        private static final DateTimeFormatter LABEL =
                DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'").withZone(ZoneOffset.UTC);

        public String label() {
            return LABEL.format(Instant.ofEpochSecond(epochMinute * 60));
        }
    }

    public record RouteSummary(String route, long hits, double averageMs, long maxMs, long serverErrors) {
    }

    /** Percent of requests that ended in 5xx (server failures). */
    public double serverErrorPercent() {
        return requests == 0 ? 0.0 : 100.0 * serverErrors / requests;
    }

    /** Percent of requests that ended in 4xx (client mistakes, unauthorised calls, missing pages). */
    public double clientErrorPercent() {
        return requests == 0 ? 0.0 : 100.0 * clientErrors / requests;
    }

    /** Turns raw counters into the sorted lists a person wants to read. */
    public static Report from(LogStats s, ReportOptions options) {
        long client = 0;
        long server = 0;
        List<StatusCount> statuses = new ArrayList<>();
        for (int status = 100; status < 600; status++) {
            long count = s.statusCount(status);
            if (count > 0) {
                statuses.add(new StatusCount(status, count));
                if (status >= 500) {
                    server += count;
                } else if (status >= 400) {
                    client += count;
                }
            }
        }

        // Ties are broken by the name or time so the order never depends on HashMap internals.
        List<MinuteCount> minutes = new ArrayList<>();
        for (Map.Entry<Long, long[]> e : s.minutes().entrySet()) {
            minutes.add(new MinuteCount(e.getKey(), e.getValue()[0], e.getValue()[1]));
        }
        minutes.sort(Comparator.comparingLong(MinuteCount::requests).reversed()
                .thenComparingLong(MinuteCount::epochMinute));

        // Minutes with the most server errors: this is where an outage shows up.
        List<MinuteCount> errorMinutes = minutes.stream()
                .filter(m -> m.serverErrors() > 0)
                .sorted(Comparator.comparingLong(MinuteCount::serverErrors).reversed()
                        .thenComparingLong(MinuteCount::epochMinute))
                .limit(options.topN())
                .toList();

        List<RouteSummary> routes = new ArrayList<>();
        for (Map.Entry<String, RouteStats> e : s.routes().entrySet()) {
            RouteStats r = e.getValue();
            routes.add(new RouteSummary(e.getKey(), r.hits(), (double) r.sumMillis() / r.hits(),
                    r.maxMillis(), r.serverErrors()));
        }
        List<RouteSummary> top = routes.stream()
                .sorted(Comparator.comparingLong(RouteSummary::hits).reversed().thenComparing(RouteSummary::route))
                .limit(options.topN())
                .toList();
        List<RouteSummary> slowest = routes.stream()
                .filter(r -> r.hits() >= options.minRouteHits())
                .sorted(Comparator.comparingDouble(RouteSummary::averageMs).reversed().thenComparing(RouteSummary::route))
                .limit(options.topN())
                .toList();

        var h = s.latency();
        Latency latency = new Latency(h.average(), h.percentile(50), h.percentile(90), h.percentile(95),
                h.percentile(99), h.max());
        return new Report(s.requests(), s.malformed(), s.totalBytes(), s.firstMinute(), s.lastMinute(),
                client, server, latency, List.copyOf(statuses),
                List.copyOf(minutes.subList(0, Math.min(options.topN(), minutes.size()))), errorMinutes,
                top, slowest);
    }
}
