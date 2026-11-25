package io.github.aachar0.loganalyzer.engine;

import io.github.aachar0.loganalyzer.parse.ResponseTimeUnit;
import io.github.aachar0.loganalyzer.stats.LogStats;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;

/**
 * Gives EVERY chunk its own virtual thread (Java 21). Virtual threads are so cheap that a million of them
 * is fine, and they shine when work spends time WAITING (network, slow disks).
 *
 * A semaphore caps how many chunks are read at the same moment. Without it, a 10 GB file split into
 * 1,250 chunks would allocate 1,250 buffers at once and run out of memory. The cap is the honest price of
 * making virtual threads safe for big files, and it is why this strategy is not magically faster than
 * the parallel one for CPU-bound parsing. The benchmark shows the real difference on your machine.
 */
public final class VirtualThreadStrategy implements ProcessingStrategy {

    private final int maxConcurrentChunks;

    public VirtualThreadStrategy(int threads) {
        this.maxConcurrentChunks = Math.max(1, threads);
    }

    @Override
    public String name() {
        return "virtual";
    }

    @Override
    public LogStats process(Path file, long chunkBytes, ResponseTimeUnit unit) throws IOException, InterruptedException {
        Semaphore permits = new Semaphore(maxConcurrentChunks);
        // ExecutorService is AutoCloseable since Java 19: try-with-resources waits for tasks and closes it.
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
             FileChannel channel = FileChannel.open(file, StandardOpenOption.READ)) {
            List<Range> ranges = ChunkPlanner.plan(channel.size(), chunkBytes);
            ExecutorCompletionService<LogStats> completion = new ExecutorCompletionService<>(executor);
            for (Range range : ranges) {
                completion.submit(() -> {
                    permits.acquire();                                   // wait for a free slot (cheap for a virtual thread)
                    try {
                        return ChunkProcessor.process(channel, range, unit);
                    } finally {
                        permits.release();
                    }
                });
            }
            LogStats total = new LogStats();
            for (int done = 0; done < ranges.size(); done++) {
                Future<LogStats> finished = completion.take();
                total.merge(finished.get());
            }
            return total;
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof IOException io) {
                throw io;
            }
            throw new IOException("A worker failed: " + cause, cause);
        }
    }
}
