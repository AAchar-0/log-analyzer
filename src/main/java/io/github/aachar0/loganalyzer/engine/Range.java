package io.github.aachar0.loganalyzer.engine;

/** A slice of a file: bytes from start (inclusive) to end (exclusive). */
public record Range(long start, long end) {
    public Range {
        if (start < 0 || end < start) {
            throw new IllegalArgumentException("Bad range " + start + ".." + end);
        }
    }
}
