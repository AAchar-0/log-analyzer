package io.github.aachar0.loganalyzer.report;

import io.github.aachar0.loganalyzer.engine.AnalysisResult;

import java.util.Locale;

/** Draws a Report as plain text for the terminal. */
public final class TextReport {

    private TextReport() {
    }

    public static String render(AnalysisResult result) {
        Report r = result.report();
        StringBuilder out = new StringBuilder();
        out.append(String.format(Locale.ROOT, "Log analysis  (strategy: %s, %,d requests, %.0f ms, %.1f MB file)%n",
                result.strategy(), r.requests(), result.millis(), result.fileBytes() / 1_000_000.0));
        out.append(String.format(Locale.ROOT, "Malformed lines skipped : %,d%n", r.malformedLines()));
        if (r.requests() == 0) {
            out.append("No valid requests found.\n");
            return out.toString();
        }
        out.append(String.format(Locale.ROOT, "Period                  : %s  to  %s%n",
                new Report.MinuteCount(r.firstMinute(), 0, 0).label(),
                new Report.MinuteCount(r.lastMinute(), 0, 0).label()));
        out.append(String.format(Locale.ROOT, "Data sent               : %.1f MB%n", r.totalBytes() / 1_000_000.0));
        out.append(String.format(Locale.ROOT, "Server errors (5xx)     : %,d  (%.2f%%)%n", r.serverErrors(), r.serverErrorPercent()));
        out.append(String.format(Locale.ROOT, "Client errors (4xx)     : %,d  (%.2f%%)%n", r.clientErrors(), r.clientErrorPercent()));
        Report.Latency l = r.latency();
        out.append(String.format(Locale.ROOT, "Response time (ms)      : avg %.1f | p50 %d | p90 %d | p95 %d | p99 %d | max %d%n",
                l.averageMs(), l.p50(), l.p90(), l.p95(), l.p99(), l.maxMs()));

        out.append("\nStatus codes\n");
        for (Report.StatusCount s : r.statuses()) {
            out.append(String.format(Locale.ROOT, "  %d  %,12d%n", s.status(), s.count()));
        }
        out.append("\nBusiest minutes\n");
        for (Report.MinuteCount m : r.busiestMinutes()) {
            out.append(String.format(Locale.ROOT, "  %s  %,8d requests  %,6d server errors%n",
                    m.label(), m.requests(), m.serverErrors()));
        }
        out.append("\nMinutes with the most server errors (look here for outages)\n");
        if (r.worstErrorMinutes().isEmpty()) {
            out.append("  none\n");
        }
        for (Report.MinuteCount m : r.worstErrorMinutes()) {
            out.append(String.format(Locale.ROOT, "  %s  %,6d server errors  of %,d requests%n",
                    m.label(), m.serverErrors(), m.requests()));
        }
        out.append("\nMost requested routes\n");
        for (Report.RouteSummary s : r.topRoutes()) {
            out.append(String.format(Locale.ROOT, "  %,10d  %-36s avg %.1f ms%n", s.hits(), s.route(), s.averageMs()));
        }
        out.append("\nSlowest routes (by average)\n");
        for (Report.RouteSummary s : r.slowestRoutes()) {
            out.append(String.format(Locale.ROOT, "  avg %8.1f ms  max %6d ms  %,9d hits  %s%n",
                    s.averageMs(), s.maxMs(), s.hits(), s.route()));
        }
        return out.toString();
    }
}
