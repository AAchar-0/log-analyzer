package io.github.aachar0.loganalyzer.stats;

/**
 * Counts how many requests took 0 ms, 1 ms, 2 ms ... up to 10,000 ms (one extra bucket holds slower ones).
 *
 * Why not keep every response time in a list and sort it? With 100 million lines that list would need
 * gigabytes of memory. A histogram needs the same ~80 KB whether there are 1,000 or 1,000,000,000 lines,
 * answers percentiles exactly (for whole milliseconds up to 10 s), and two histograms merge by simple
 * addition, which is exactly what parallel workers need.
 */
public final class LatencyHistogram {

    public static final int MAX_MS = 10_000;

    private final long[] counts = new long[MAX_MS + 2];   // index MAX_MS+1 = "slower than 10 s"
    private long total;
    private long sum;
    private long max;

    public void record(int millis) {
        counts[millis > MAX_MS ? MAX_MS + 1 : millis]++;
        total++;
        sum += millis;
        if (millis > max) {
            max = millis;
        }
    }

    /** Adds all counts of another histogram into this one. */
    public void merge(LatencyHistogram other) {
        for (int i = 0; i < counts.length; i++) {
            counts[i] += other.counts[i];
        }
        total += other.total;
        sum += other.sum;
        max = Math.max(max, other.max);
    }

    public long count() {
        return total;
    }

    public long max() {
        return max;
    }

    public double average() {
        return total == 0 ? 0.0 : (double) sum / total;
    }

    /**
     * Nearest-rank percentile: the smallest value v such that at least p percent of requests took v or less.
     * Example: percentile(95) = "95% of requests were this fast or faster".
     */
    public long percentile(double p) {
        if (total == 0) {
            return 0;
        }
        long rank = Math.max(1, (long) Math.ceil(p / 100.0 * total));
        long running = 0;
        for (int i = 0; i < counts.length; i++) {
            running += counts[i];
            if (running >= rank) {
                return i > MAX_MS ? max : i;               // the overflow bucket reports the true maximum
            }
        }
        return max;
    }
}
