package io.github.aachar0.loganalyzer.engine;

import io.github.aachar0.loganalyzer.report.Report;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Times every strategy fairly:
 *  1. warm-up runs first (the first runs are slow while Java compiles hot code and the file cache fills),
 *  2. then several measured runs, in rotating order so no strategy always goes first,
 *  3. report the MEDIAN (robust against one unlucky run) and the fastest run,
 *  4. check that all strategies produced exactly the same report.
 * A speed-up is only worth publishing when the answers are identical.
 */
public final class Benchmark {

    /** @param speedup how many times faster than sequential, based on medians (1.0 = same speed) */
    public record Timing(String strategy, double medianMs, double minMs, double speedup, List<Double> runsMs) {
    }

    public record Outcome(long fileBytes, long requests, int cores, int warmups, int runs,
                          boolean identical, List<Timing> timings) {
    }

    private Benchmark() {
    }

    public static Outcome run(Path file, int warmups, int runs, long chunkBytes, int threads, String timeUnitText)
            throws IOException, InterruptedException {
        if (runs < 1 || warmups < 0) {
            throw new IllegalArgumentException("runs must be at least 1 and warmups at least 0");
        }
        List<ProcessingStrategy> strategies = ProcessingStrategy.all(threads);
        List<List<Double>> times = new ArrayList<>();
        for (int i = 0; i < strategies.size(); i++) {
            times.add(new ArrayList<>());
        }
        Report reference = null;
        boolean identical = true;

        for (int round = 0; round < warmups + runs; round++) {
            for (int k = 0; k < strategies.size(); k++) {
                int index = (k + round) % strategies.size();                   // rotate the starting strategy
                ProcessingStrategy strategy = strategies.get(index);
                AnalysisConfig config = AnalysisConfig.builder(file).strategy(strategy.name()).threads(threads)
                        .chunkBytes(chunkBytes)
                        .timeUnit(io.github.aachar0.loganalyzer.parse.ResponseTimeUnit.fromText(timeUnitText))
                        .build();
                AnalysisResult result = Analyzer.run(config);
                if (reference == null) {
                    reference = result.report();
                } else if (!reference.equals(result.report())) {
                    identical = false;
                }
                if (round >= warmups) {
                    times.get(index).add(result.millis());
                }
            }
        }

        double sequentialMedian = median(times.get(0));
        List<Timing> timings = new ArrayList<>();
        for (int i = 0; i < strategies.size(); i++) {
            double median = median(times.get(i));
            double min = times.get(i).stream().mapToDouble(Double::doubleValue).min().orElse(0);
            timings.add(new Timing(strategies.get(i).name(), median, min,
                    median == 0 ? 0 : sequentialMedian / median, List.copyOf(times.get(i))));
        }
        long size = java.nio.file.Files.size(file);
        return new Outcome(size, reference == null ? 0 : reference.requests(),
                Runtime.getRuntime().availableProcessors(), warmups, runs, identical, timings);
    }

    static double median(List<Double> values) {
        double[] sorted = values.stream().mapToDouble(Double::doubleValue).sorted().toArray();
        if (sorted.length == 0) {
            return 0;
        }
        int mid = sorted.length / 2;
        return sorted.length % 2 == 1 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2.0;
    }

    /** Text table for the terminal. */
    public static String toText(Outcome o) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format(java.util.Locale.ROOT,
                "Benchmark: %,d requests, %.1f MB, %d CPU cores, %d warm-up + %d measured runs each%n",
                o.requests(), o.fileBytes() / 1_000_000.0, o.cores(), o.warmups(), o.runs()));
        sb.append(String.format("%-12s %12s %12s %10s%n", "strategy", "median (ms)", "fastest (ms)", "speed-up"));
        for (Timing t : o.timings()) {
            sb.append(String.format(java.util.Locale.ROOT, "%-12s %12.1f %12.1f %9.2fx%n",
                    t.strategy(), t.medianMs(), t.minMs(), t.speedup()));
        }
        sb.append(o.identical() ? "All strategies produced identical reports.\n"
                : "WARNING: strategies produced DIFFERENT reports. Do not trust these numbers.\n");
        return sb.toString();
    }

    /** JSON for the web page. */
    public static String toJson(Outcome o) {
        StringBuilder sb = new StringBuilder("{");
        sb.append("\"fileBytes\":").append(o.fileBytes()).append(",\"requests\":").append(o.requests())
                .append(",\"cores\":").append(o.cores()).append(",\"warmups\":").append(o.warmups())
                .append(",\"runs\":").append(o.runs()).append(",\"identical\":").append(o.identical())
                .append(",\"timings\":[");
        for (int i = 0; i < o.timings().size(); i++) {
            Timing t = o.timings().get(i);
            if (i > 0) {
                sb.append(',');
            }
            sb.append("{\"strategy\":").append(io.github.aachar0.loganalyzer.report.JsonReport.quote(t.strategy()))
                    .append(",\"medianMs\":").append(io.github.aachar0.loganalyzer.report.JsonReport.number(t.medianMs()))
                    .append(",\"minMs\":").append(io.github.aachar0.loganalyzer.report.JsonReport.number(t.minMs()))
                    .append(",\"speedup\":").append(io.github.aachar0.loganalyzer.report.JsonReport.number(t.speedup()))
                    .append('}');
        }
        return sb.append("]}").toString();
    }
}
