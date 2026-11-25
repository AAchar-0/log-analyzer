package io.github.aachar0.loganalyzer.engine;

import java.util.ArrayList;
import java.util.List;

/** Cuts a file of a given size into equal byte ranges (the last one may be shorter). */
public final class ChunkPlanner {

    private ChunkPlanner() {
    }

    public static List<Range> plan(long fileSize, long chunkBytes) {
        if (chunkBytes < 1) {
            throw new IllegalArgumentException("chunkBytes must be at least 1");
        }
        List<Range> ranges = new ArrayList<>();
        for (long start = 0; start < fileSize; start += chunkBytes) {
            ranges.add(new Range(start, Math.min(fileSize, start + chunkBytes)));
        }
        if (ranges.isEmpty()) {
            ranges.add(new Range(0, 0));                    // an empty file still produces one (empty) result
        }
        return ranges;
    }
}
