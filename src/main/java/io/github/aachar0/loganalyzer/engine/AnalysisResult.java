package io.github.aachar0.loganalyzer.engine;

import io.github.aachar0.loganalyzer.report.Report;

/**
 * What one run produced: the report, which strategy made it, and how long the counting took.
 * The time covers reading and counting only (not building the report text).
 */
public record AnalysisResult(String strategy, long nanos, long fileBytes, Report report) {

    public double millis() {
        return nanos / 1_000_000.0;
    }
}
