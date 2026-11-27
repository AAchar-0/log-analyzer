package io.github.aachar0.loganalyzer.engine;

import io.github.aachar0.loganalyzer.parse.ResponseTimeUnit;
import io.github.aachar0.loganalyzer.report.ReportOptions;

import java.nio.file.Path;
import java.util.Set;

/**
 * Settings for one analysis run, created with the BUILDER PATTERN:
 * <pre>
 * AnalysisConfig config = AnalysisConfig.builder(Path.of("access.log"))
 *         .strategy("parallel").topN(5).build();
 * </pre>
 * A builder is handy when a class has many optional settings with sensible defaults: the caller names
 * only what they want to change, and build() checks that the final combination is valid.
 */
public final class AnalysisConfig {

    public static final long DEFAULT_CHUNK_BYTES = 8L * 1024 * 1024;   // 8 MiB per chunk

    private final Path file;
    private final ProcessingStrategy strategy;
    private final long chunkBytes;
    private final ResponseTimeUnit timeUnit;
    private final ReportOptions reportOptions;

    private AnalysisConfig(Builder b) {
        this.file = b.file;
        this.strategy = ProcessingStrategy.byName(b.strategyName, b.threads);
        this.chunkBytes = b.chunkBytes;
        this.timeUnit = b.timeUnit;
        this.reportOptions = new ReportOptions(b.topN, b.minRouteHits, b.blockedCountries, b.allowedCountries);
    }

    public Path file() {
        return file;
    }

    public ProcessingStrategy strategy() {
        return strategy;
    }

    public long chunkBytes() {
        return chunkBytes;
    }

    public ResponseTimeUnit timeUnit() {
        return timeUnit;
    }

    public ReportOptions reportOptions() {
        return reportOptions;
    }

    /**
     * Picks a chunk size that gives every worker several chunks to share (so a slow chunk does not leave
     * the others idle) but never less than 1 MiB (tiny chunks waste time on overhead) or more than 8 MiB.
     */
    public static long suggestChunkBytes(long fileSize, int threads) {
        long perChunk = fileSize / Math.max(1, threads * 4L) + 1;
        return Math.max(1024L * 1024, Math.min(DEFAULT_CHUNK_BYTES, perChunk));
    }

    public static Builder builder(Path file) {
        return new Builder(file);
    }

    public static final class Builder {
        private final Path file;
        private String strategyName = "parallel";
        private int threads = Runtime.getRuntime().availableProcessors();
        private long chunkBytes = DEFAULT_CHUNK_BYTES;
        private ResponseTimeUnit timeUnit = ResponseTimeUnit.MILLIS;
        private int topN = 10;
        private int minRouteHits = 10;
        private Set<String> blockedCountries = Set.of();
        private Set<String> allowedCountries = Set.of();

        private Builder(Path file) {
            this.file = java.util.Objects.requireNonNull(file, "file");
        }

        public Builder strategy(String name) {
            this.strategyName = name;
            return this;                       // returning "this" lets calls be chained: .a().b().c()
        }

        public Builder threads(int threads) {
            this.threads = threads;
            return this;
        }

        public Builder chunkBytes(long chunkBytes) {
            this.chunkBytes = chunkBytes;
            return this;
        }

        public Builder timeUnit(ResponseTimeUnit unit) {
            this.timeUnit = unit;
            return this;
        }

        public Builder topN(int topN) {
            this.topN = topN;
            return this;
        }

        public Builder minRouteHits(int minRouteHits) {
            this.minRouteHits = minRouteHits;
            return this;
        }

        /** Areas the business does not deal in (two-letter codes): a login from there is treated as malicious. */
        public Builder blockedCountries(Set<String> codes) {
            this.blockedCountries = java.util.Objects.requireNonNull(codes, "codes");
            return this;
        }

        /** Optional: when not empty, a login from any country NOT listed is treated as malicious. */
        public Builder allowedCountries(Set<String> codes) {
            this.allowedCountries = java.util.Objects.requireNonNull(codes, "codes");
            return this;
        }

        public AnalysisConfig build() {
            if (threads < 1 || threads > 256) {
                throw new IllegalArgumentException("threads must be between 1 and 256");
            }
            if (chunkBytes < 1) {
                throw new IllegalArgumentException("chunkBytes must be at least 1");
            }
            if (topN < 1 || topN > 100) {
                throw new IllegalArgumentException("top must be between 1 and 100");
            }
            if (minRouteHits < 1) {
                throw new IllegalArgumentException("minRouteHits must be at least 1");
            }
            return new AnalysisConfig(this);
        }
    }
}
