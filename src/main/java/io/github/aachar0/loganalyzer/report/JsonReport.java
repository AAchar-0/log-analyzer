package io.github.aachar0.loganalyzer.report;

import io.github.aachar0.loganalyzer.engine.AnalysisResult;

import java.util.List;
import java.util.Locale;
import java.util.function.Function;

/**
 * Writes JSON by hand so the project needs no libraries (nothing to download, update or secure).
 * The only tricky part is escaping text: log lines are untrusted input, so every string goes through quote().
 */
public final class JsonReport {

    private JsonReport() {
    }

    public static String render(AnalysisResult result) {
        return "{\"strategy\":" + quote(result.strategy())
                + ",\"millis\":" + number(result.millis())
                + ",\"fileBytes\":" + result.fileBytes()
                + ",\"report\":" + report(result.report()) + "}";
    }

    public static String report(Report r) {
        StringBuilder sb = new StringBuilder(2048);
        sb.append('{');
        sb.append("\"requests\":").append(r.requests());
        sb.append(",\"malformedLines\":").append(r.malformedLines());
        sb.append(",\"totalBytes\":").append(r.totalBytes());
        sb.append(",\"firstMinute\":").append(quote(label(r.firstMinute())));
        sb.append(",\"lastMinute\":").append(quote(label(r.lastMinute())));
        sb.append(",\"clientErrors\":").append(r.clientErrors());
        sb.append(",\"serverErrors\":").append(r.serverErrors());
        sb.append(",\"clientErrorPercent\":").append(number(r.clientErrorPercent()));
        sb.append(",\"serverErrorPercent\":").append(number(r.serverErrorPercent()));
        Report.Latency l = r.latency();
        sb.append(",\"latency\":{\"averageMs\":").append(number(l.averageMs()))
                .append(",\"p50\":").append(l.p50()).append(",\"p90\":").append(l.p90())
                .append(",\"p95\":").append(l.p95()).append(",\"p99\":").append(l.p99())
                .append(",\"maxMs\":").append(l.maxMs()).append('}');
        sb.append(",\"statuses\":").append(array(r.statuses(),
                s -> "{\"status\":" + s.status() + ",\"count\":" + s.count() + "}"));
        sb.append(",\"busiestMinutes\":").append(array(r.busiestMinutes(),
                m -> "{\"minute\":" + quote(m.label()) + ",\"requests\":" + m.requests()
                        + ",\"serverErrors\":" + m.serverErrors() + "}"));
        sb.append(",\"worstErrorMinutes\":").append(array(r.worstErrorMinutes(),
                m -> "{\"minute\":" + quote(m.label()) + ",\"requests\":" + m.requests()
                        + ",\"serverErrors\":" + m.serverErrors() + "}"));
        sb.append(",\"topRoutes\":").append(array(r.topRoutes(), JsonReport::route));
        sb.append(",\"slowestRoutes\":").append(array(r.slowestRoutes(), JsonReport::route));
        return sb.append('}').toString();
    }

    private static String route(Report.RouteSummary s) {
        return "{\"route\":" + quote(s.route()) + ",\"hits\":" + s.hits() + ",\"averageMs\":" + number(s.averageMs())
                + ",\"maxMs\":" + s.maxMs() + ",\"serverErrors\":" + s.serverErrors() + "}";
    }

    private static String label(long minute) {
        return new Report.MinuteCount(minute, 0, 0).label();
    }

    private static <T> String array(List<T> items, Function<T, String> toJson) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append(toJson.apply(items.get(i)));
        }
        return sb.append(']').toString();
    }

    /** JSON has no NaN or Infinity, so those become 0. Two decimals are plenty for a report. */
    public static String number(double value) {
        return Double.isFinite(value) ? String.format(Locale.ROOT, "%.2f", value) : "0";
    }

    /** Wraps text in quotes and escapes everything JSON requires (quotes, backslashes, control characters). */
    public static String quote(String text) {
        StringBuilder sb = new StringBuilder(text.length() + 2).append('"');
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    // < > & are escaped too, so the JSON stays harmless even if someone pastes it into an HTML page.
                    if (c < 0x20 || c > 0x7E || c == '<' || c == '>' || c == '&') {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.append('"').toString();
    }
}
