package io.github.aachar0.loganalyzer;

import io.github.aachar0.loganalyzer.engine.AnalysisConfig;
import io.github.aachar0.loganalyzer.engine.Analyzer;
import io.github.aachar0.loganalyzer.gen.LogGenerator;
import io.github.aachar0.loganalyzer.report.Report;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The most important tests of the project: whatever the strategy, thread count or chunk size,
 * every line must be counted exactly once and the reports must be identical.
 */
class StrategiesAgreeTest {

    private static final String LINE =
            "192.0.2.7 - - [01/Nov/2026:10:15:32 +0000] \"GET /api/products/42 HTTP/1.1\" 200 100 10";
    private static final String[] STRATEGIES = {"sequential", "parallel", "virtual"};

    @TempDir
    Path dir;

    private Report analyse(Path file, String strategy, long chunkBytes) throws Exception {
        return Analyzer.run(AnalysisConfig.builder(file).strategy(strategy).threads(4)
                .chunkBytes(chunkBytes).minRouteHits(1).build()).report();
    }

    private void assertAllAgree(Path file, long expectedRequests, long expectedMalformed, long... chunkSizes)
            throws Exception {
        Report reference = analyse(file, "sequential", 1 << 20);
        assertEquals(expectedRequests, reference.requests());
        assertEquals(expectedMalformed, reference.malformedLines());
        for (long chunk : chunkSizes) {
            for (String strategy : STRATEGIES) {
                Report r = analyse(file, strategy, chunk);
                assertEquals(reference, r, strategy + " with chunk size " + chunk + " differs");
            }
        }
    }

    @Test
    void generatedLogGivesIdenticalReportsForAnyChunkSize() throws Exception {
        Path file = dir.resolve("generated.log");
        LogGenerator.generate(file, 20_000, 7);
        // 1000 bytes is smaller than ten lines; 65,537 is not a "round" number, so cuts land everywhere.
        assertAllAgree(file, 20_000, 0, 1000, 4096, 65_537, 1 << 20);
    }

    @Test
    void chunksSmallerThanOneLineStillCountEveryLineOnce() throws Exception {
        Path file = dir.resolve("tiny.log");
        LogGenerator.generate(file, 300, 3);
        assertAllAgree(file, 300, 0, 17, 50, 97);
    }

    @Test
    void lastLineWithoutNewlineIsCounted() throws Exception {
        Path file = dir.resolve("nonewline.log");
        Files.writeString(file, LINE + "\n" + LINE + "\n" + LINE, StandardCharsets.US_ASCII);
        assertAllAgree(file, 3, 0, 10, 60, 1000);
    }

    @Test
    void windowsLineEndingsAreAccepted() throws Exception {
        Path file = dir.resolve("crlf.log");
        Files.writeString(file, LINE + "\r\n" + LINE + "\r\n", StandardCharsets.US_ASCII);
        assertAllAgree(file, 2, 0, 10, 1000);
    }

    @Test
    void emptyAndBlankFilesGiveZeroRequests() throws Exception {
        Path empty = dir.resolve("empty.log");
        Files.write(empty, new byte[0]);
        assertAllAgree(empty, 0, 0, 100);
        Path blank = dir.resolve("blank.log");
        Files.writeString(blank, "\n\n", StandardCharsets.US_ASCII);
        assertAllAgree(blank, 0, 2, 1, 100);               // two empty lines are two malformed lines
    }

    @Test
    void malformedLinesAreCountedNotCrashed() throws Exception {
        Path file = dir.resolve("mixed.log");
        Files.writeString(file, LINE + "\nthis is not a log line\n" + LINE + "\n\u00e9\u00e8 bytes \u00ff\n" + LINE + "\n",
                StandardCharsets.ISO_8859_1);
        assertAllAgree(file, 3, 2, 8, 50, 1000);
    }

    @Test
    void aLineLongerThanTheReadBufferIsSkippedAsMalformed() throws Exception {
        Path file = dir.resolve("huge-line.log");
        String huge = "x".repeat(600_000);                   // bigger than the 256 KB buffer
        Files.writeString(file, LINE + "\n" + huge + "\n" + LINE + "\n", StandardCharsets.US_ASCII);
        assertAllAgree(file, 2, 1, 100_000, 300_000, 1 << 20);
    }

    @Test
    void reportNumbersAreCorrectForAHandMadeLog() throws Exception {
        Path file = dir.resolve("hand.log");
        StringBuilder sb = new StringBuilder();
        // minute 10:15: three requests, one of them a 500; minute 10:16: one request.
        sb.append("1.1.1.1 - - [01/Nov/2026:10:15:01 +0000] \"GET /api/a/1 HTTP/1.1\" 200 10 10\n");
        sb.append("1.1.1.1 - - [01/Nov/2026:10:15:02 +0000] \"GET /api/a/2 HTTP/1.1\" 200 10 30\n");
        sb.append("1.1.1.1 - - [01/Nov/2026:10:15:03 +0000] \"POST /api/b HTTP/1.1\" 500 10 200\n");
        sb.append("1.1.1.1 - - [01/Nov/2026:10:16:00 +0000] \"GET /api/missing HTTP/1.1\" 404 10 20\n");
        Files.writeString(file, sb.toString(), StandardCharsets.US_ASCII);

        Report r = analyse(file, "parallel", 1 << 20);
        assertEquals(4L, r.requests());
        assertEquals(1L, r.serverErrors());
        assertEquals(1L, r.clientErrors());
        assertEquals(25.0, r.serverErrorPercent(), 0.0001);
        assertEquals(3L, r.busiestMinutes().get(0).requests());
        assertEquals("2026-11-01 10:15 UTC", r.busiestMinutes().get(0).label());
        assertEquals(1, r.worstErrorMinutes().size());
        assertEquals(65.0, r.latency().averageMs(), 0.0001);
        assertEquals(200L, r.latency().maxMs());
        assertEquals("POST /api/b", r.slowestRoutes().get(0).route());
        assertEquals("GET /api/a/{id}", r.topRoutes().get(0).route());
        assertEquals(2L, r.topRoutes().get(0).hits());
    }

    @Test
    void invalidSettingsAreRejected() throws IOException {
        Path file = dir.resolve("any.log");
        Files.write(file, new byte[0]);
        assertThrows(IllegalArgumentException.class, () -> AnalysisConfig.builder(file).strategy("warp-speed").build());
        assertThrows(IllegalArgumentException.class, () -> AnalysisConfig.builder(file).threads(0).build());
        assertThrows(IllegalArgumentException.class, () -> AnalysisConfig.builder(file).chunkBytes(0).build());
    }
}
