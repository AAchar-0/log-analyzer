package io.github.aachar0.loganalyzer.stats;

/** Running totals for one route such as "GET /api/products/{id}". Mutable and NOT thread-safe on purpose. */
public final class RouteStats {
    long hits;
    long serverErrors;
    long sumMillis;
    long maxMillis;

    void add(int millis, boolean serverError) {
        hits++;
        sumMillis += millis;
        if (millis > maxMillis) {
            maxMillis = millis;
        }
        if (serverError) {
            serverErrors++;
        }
    }

    void merge(RouteStats other) {
        hits += other.hits;
        serverErrors += other.serverErrors;
        sumMillis += other.sumMillis;
        maxMillis = Math.max(maxMillis, other.maxMillis);
    }

    public long hits() {
        return hits;
    }

    public long serverErrors() {
        return serverErrors;
    }

    public long sumMillis() {
        return sumMillis;
    }

    public long maxMillis() {
        return maxMillis;
    }
}
