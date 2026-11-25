package io.github.aachar0.loganalyzer.engine;

import io.github.aachar0.loganalyzer.parse.ResponseTimeUnit;
import io.github.aachar0.loganalyzer.stats.LogStats;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/** The baseline: one thread reads the file from the first byte to the last. Simple and the reference answer. */
public final class SequentialStrategy implements ProcessingStrategy {

    @Override
    public String name() {
        return "sequential";
    }

    @Override
    public LogStats process(Path file, long chunkBytes, ResponseTimeUnit unit) throws IOException {
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ)) {
            return ChunkProcessor.process(channel, new Range(0, channel.size()), unit);   // ONE range = whole file
        }
    }
}
