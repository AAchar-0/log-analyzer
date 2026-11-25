package io.github.aachar0.loganalyzer.engine;

import io.github.aachar0.loganalyzer.report.Report;
import io.github.aachar0.loganalyzer.stats.LogStats;

import java.io.IOException;
import java.nio.file.Files;

/** The one entry point: give it a config, get a result. Used by the command line and the web server. */
public final class Analyzer {

    private Analyzer() {
    }

    public static AnalysisResult run(AnalysisConfig config) throws IOException, InterruptedException {
        long size = Files.size(config.file());
        long started = System.nanoTime();
        LogStats stats = config.strategy().process(config.file(), config.chunkBytes(), config.timeUnit());
        long nanos = System.nanoTime() - started;
        return new AnalysisResult(config.strategy().name(), nanos, size, Report.from(stats, config.reportOptions()));
    }
}
