package io.github.aachar0.loganalyzer.engine;

import io.github.aachar0.loganalyzer.parse.ResponseTimeUnit;
import io.github.aachar0.loganalyzer.stats.LogStats;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;

/**
 * STRATEGY PATTERN: three interchangeable ways to do the same job behind one interface.
 * The rest of the program only calls process(); it does not care which way is used.
 *
 * "sealed ... permits" lists every implementation, so a switch over strategies can be checked by the compiler.
 */
public sealed interface ProcessingStrategy permits SequentialStrategy, ParallelStrategy, VirtualThreadStrategy {

    /** Short name used on the command line and in the web page: sequential, parallel or virtual. */
    String name();

    /** Reads the whole file and returns the combined counters. */
    LogStats process(Path file, long chunkBytes, ResponseTimeUnit unit) throws IOException, InterruptedException;

    /** Creates a strategy from its name. "threads" only matters for the parallel and virtual versions. */
    static ProcessingStrategy byName(String name, int threads) {
        return switch (name.toLowerCase(Locale.ROOT)) {
            case "sequential", "seq" -> new SequentialStrategy();
            case "parallel", "par" -> new ParallelStrategy(threads);
            case "virtual", "virtual-threads" -> new VirtualThreadStrategy(threads);
            default -> throw new IllegalArgumentException(
                    "Unknown strategy '" + name + "'. Use sequential, parallel or virtual.");
        };
    }

    /** All three, in the order they are shown in reports. */
    static List<ProcessingStrategy> all(int threads) {
        return List.of(new SequentialStrategy(), new ParallelStrategy(threads), new VirtualThreadStrategy(threads));
    }
}
