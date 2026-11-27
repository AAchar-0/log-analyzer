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
        appendGeo(out, r.geo());
        return out.toString();
    }

    /** Login attempts by country, with the nearest cities and the areas the business does not deal in. */
    private static void appendGeo(StringBuilder out, GeoReport g) {
        out.append("\nLogin attempts by country\n");
        if (g.loginAttempts() == 0) {
            out.append("  no login attempts in this log (POST requests to a route ending in /login or /signin)\n");
            return;
        }
        if (!g.available()) {
            out.append("  location data is not available, so countries cannot be shown\n");
            return;
        }
        out.append(String.format(Locale.ROOT, "  %,d login attempts: %,d placed on a map, %,d with an unknown location "
                + "(private, reserved or unlisted address)%n", g.loginAttempts(), g.locatedAttempts(), g.unknownAttempts()));
        if (g.blockedCountries().isEmpty() && g.allowedCountries().isEmpty()) {
            out.append("  No areas configured. Use --blocked-countries KE,US (areas you do NOT deal in) to flag logins as malicious.\n");
        } else {
            out.append(String.format(Locale.ROOT, "  Areas you do not deal in: %s%s%n",
                    g.blockedCountries().isEmpty() ? "none listed" : String.join(", ", g.blockedCountries()),
                    g.allowedCountries().isEmpty() ? "" : "; only allowed: " + String.join(", ", g.allowedCountries())));
            GeoReport.Restricted x = g.restricted();
            out.append(String.format(Locale.ROOT, "  MALICIOUS (restricted areas): %,d attempts from %d countries (%.2f%% of placed attempts), "
                            + "%,d of them SUCCEEDED%n", x.attempts(), x.countries(), g.restrictedPercent(), x.successes()));
        }
        appendCountries(out, "Top countries trying to log in", g.topCountries());
        appendCountries(out, "Bottom countries (fewest attempts)", g.bottomCountries());
        if (!g.restrictedCountries().isEmpty()) {
            appendCountries(out, "Restricted areas trying to log in (treated as malicious)", g.restrictedCountries());
        }
        out.append("  Locations are estimates from the IP address. ").append(g.source()).append('\n');
    }

    private static void appendCountries(StringBuilder out, String title, java.util.List<GeoReport.CountryLogins> list) {
        out.append('\n').append(title).append('\n');
        for (GeoReport.CountryLogins c : list) {
            out.append(String.format(Locale.ROOT, "  %-2s %-28s %,10d attempts  %,9d ok  %,9d failed%s%n",
                    c.code(), c.name(), c.attempts(), c.successes(), c.failures(), c.restricted() ? "  [MALICIOUS AREA]" : ""));
            StringBuilder cities = new StringBuilder();
            for (GeoReport.CityLogins city : c.cities()) {
                if (cities.length() > 0) {
                    cities.append(", ");
                }
                boolean twin = c.cities().stream().filter(o -> o != city && o.city().equals(city.city())).count() > 0;
                String name = city.city().isEmpty() ? "(city unknown)" : city.city();
                cities.append(name).append(twin && !city.region().isEmpty() ? " - " + city.region() : "")
                        .append(" ").append(city.attempts());
            }
            out.append("       nearest cities: ").append(cities.length() == 0 ? "-" : cities).append('\n');
        }
    }
}
