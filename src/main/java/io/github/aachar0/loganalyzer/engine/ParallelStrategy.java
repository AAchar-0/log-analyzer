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

/**
 * Cuts the file into chunks and lets a fixed pool of platform threads (one per CPU core by default)
 * process them at the same time. Each chunk returns its own LogStats; the calling thread merges them as
 * they finish, so only a few results are in memory at once.
 *
 * Best for CPU-bound work such as parsing, because more threads than cores cannot make a core faster.
 */
public final class ParallelStrategy implements ProcessingStrategy {

    private final int threads;

    public ParallelStrategy(int threads) {
        this.threads = Math.max(1, threads);
    }

    @Override
    public String name() {
        return "parallel";
    }

    @Override
    public LogStats process(Path file, long chunkBytes, ResponseTimeUnit unit) throws IOException, InterruptedException {
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ)) {
            List<Range> ranges = ChunkPlanner.plan(channel.size(), chunkBytes);
            ExecutorCompletionService<LogStats> completion = new ExecutorCompletionService<>(pool);
            for (Range range : ranges) {
                completion.submit(() -> ChunkProcessor.process(channel, range, unit));   // positional reads are thread-safe
            }
            LogStats total = new LogStats();
            for (int done = 0; done < ranges.size(); done++) {
                Future<LogStats> finished = completion.take();                           // waits for the next finished chunk
                total.merge(finished.get());
            }
            return total;
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof IOException io) {                                       // pattern matching for instanceof
                throw io;
            }
            throw new IOException("A worker failed: " + cause, cause);
        } finally {
            pool.shutdownNow();                                                          // always release the threads
        }
    }
}
