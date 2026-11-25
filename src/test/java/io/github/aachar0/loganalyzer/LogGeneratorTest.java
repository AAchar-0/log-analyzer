package io.github.aachar0.loganalyzer;

import io.github.aachar0.loganalyzer.engine.AnalysisConfig;
import io.github.aachar0.loganalyzer.engine.Analyzer;
import io.github.aachar0.loganalyzer.gen.LogGenerator;
import io.github.aachar0.loganalyzer.report.Report;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LogGeneratorTest {

    @TempDir
    Path dir;

    @Test
    void sameSeedGivesIdenticalFiles() throws Exception {
        Path a = dir.resolve("a.log");
        Path b = dir.resolve("b.log");
        LogGenerator.generate(a, 5_000, 99);
        LogGenerator.generate(b, 5_000, 99);
        assertTrue(Arrays.equals(Files.readAllBytes(a), Files.readAllBytes(b)));
    }

    @Test
    void differentSeedsGiveDifferentFiles() throws Exception {
        Path a = dir.resolve("a.log");
        Path b = dir.resolve("b.log");
        LogGenerator.generate(a, 5_000, 1);
        LogGenerator.generate(b, 5_000, 2);
        assertNotEquals(Files.readString(a), Files.readString(b));
    }

    @Test
    void writesExactlyTheRequestedNumberOfParsableLines() throws Exception {
        Path file = dir.resolve("c.log");
        LogGenerator.generate(file, 12_345, 5);
        try (var lines = Files.lines(file)) {
            assertEquals(12_345L, lines.count());
        }
        Report r = Analyzer.run(AnalysisConfig.builder(file).strategy("sequential").build()).report();
        assertEquals(12_345L, r.requests());
        assertEquals(0L, r.malformedLines());
    }

    @Test
    void theLogContainsAnOutageToFind() throws Exception {
        Path file = dir.resolve("d.log");
        LogGenerator.generate(file, 200_000, 42);
        Report r = Analyzer.run(AnalysisConfig.builder(file).strategy("parallel").build()).report();
        assertTrue(r.serverErrors() > 100, "the planted incident should create many 5xx errors");
        assertTrue(r.worstErrorMinutes().get(0).serverErrors() > 50);
    }

    @Test
    void zeroLinesMakesAnEmptyFile() throws Exception {
        Path file = dir.resolve("e.log");
        assertEquals(0L, LogGenerator.generate(file, 0, 1));
    }
}
