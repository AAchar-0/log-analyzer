package io.github.aachar0.loganalyzer.report;

/**
 * @param topN         how many rows to show in each "top" list
 * @param minRouteHits routes with fewer requests than this are left out of the "slowest" list,
 *                     because the average of 2 requests says very little
 */
public record ReportOptions(int topN, int minRouteHits) {
    public static ReportOptions defaults() {
        return new ReportOptions(10, 10);
    }
}
