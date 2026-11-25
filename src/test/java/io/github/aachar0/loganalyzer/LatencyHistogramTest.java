package io.github.aachar0.loganalyzer;

import io.github.aachar0.loganalyzer.stats.LatencyHistogram;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class LatencyHistogramTest {

    @Test
    void percentilesUseNearestRank() {
        LatencyHistogram h = new LatencyHistogram();
        for (int ms = 1; ms <= 100; ms++) {
            h.record(ms);
        }
        assertEquals(50L, h.percentile(50));
        assertEquals(90L, h.percentile(90));
        assertEquals(95L, h.percentile(95));
        assertEquals(99L, h.percentile(99));
        assertEquals(100L, h.percentile(100));
        assertEquals(100L, h.max());
        assertEquals(50.5, h.average(), 0.0001);
    }

    @Test
    void emptyHistogramIsAllZero() {
        LatencyHistogram h = new LatencyHistogram();
        assertEquals(0L, h.percentile(95));
        assertEquals(0.0, h.average(), 0.0);
        assertEquals(0L, h.max());
    }

    @Test
    void mergingTwoHalvesEqualsOneWhole() {
        LatencyHistogram whole = new LatencyHistogram();
        LatencyHistogram a = new LatencyHistogram();
        LatencyHistogram b = new LatencyHistogram();
        for (int ms = 1; ms <= 1000; ms++) {
            whole.record(ms);
            (ms % 2 == 0 ? a : b).record(ms);
        }
        a.merge(b);
        for (double p : new double[]{1, 25, 50, 90, 99, 100}) {
            assertEquals(whole.percentile(p), a.percentile(p));
        }
        assertEquals(whole.count(), a.count());
        assertEquals(whole.average(), a.average(), 0.0001);
    }

    @Test
    void verySlowRequestsReportTheTrueMaximum() {
        LatencyHistogram h = new LatencyHistogram();
        h.record(5);
        h.record(25_000);
        assertEquals(25_000L, h.percentile(100));
        assertEquals(25_000L, h.max());
    }
}
