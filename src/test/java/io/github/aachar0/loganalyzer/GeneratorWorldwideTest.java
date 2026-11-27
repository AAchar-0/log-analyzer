package io.github.aachar0.loganalyzer;

import io.github.aachar0.loganalyzer.engine.AnalysisConfig;
import io.github.aachar0.loganalyzer.engine.Analyzer;
import io.github.aachar0.loganalyzer.gen.LogGenerator;
import io.github.aachar0.loganalyzer.report.GeoReport;
import io.github.aachar0.loganalyzer.report.Report;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GeneratorWorldwideTest {

    @TempDir
    Path dir;

    @Test
    void theDefaultModeIsUnchanged() throws Exception {
        Path a = dir.resolve("a.log");
        Path b = dir.resolve("b.log");
        LogGenerator.generate(a, 8_000, 5);
        LogGenerator.generate(b, 8_000, 5, false);
        assertTrue(Arrays.equals(Files.readAllBytes(a), Files.readAllBytes(b)));
        assertTrue(Files.readString(a).startsWith("19") || Files.readString(a).startsWith("2"), "documentation addresses");
    }

    @Test
    void worldwideModeKeepsTheSameShapeOfTraffic() throws Exception {
        Path normal = dir.resolve("n.log");
        Path world = dir.resolve("w.log");
        LogGenerator.generate(normal, 20_000, 9, false);
        LogGenerator.generate(world, 20_000, 9, true);
        assertEquals(Files.readAllLines(normal).size(), Files.readAllLines(world).size());
        assertNotEquals(Files.readString(normal), Files.readString(world));
        Report a = Analyzer.run(AnalysisConfig.builder(normal).strategy("sequential").build()).report();
        Report w = Analyzer.run(AnalysisConfig.builder(world).strategy("sequential").build()).report();
        assertEquals(a.requests(), w.requests());
        assertEquals(0, w.malformedLines());
        assertEquals(a.topRoutes().get(0).route(), w.topRoutes().get(0).route());
    }

    @Test
    void worldwideLogsAreReproducibleAndReadByEveryStrategy() throws Exception {
        Path a = dir.resolve("a.log");
        Path b = dir.resolve("b.log");
        LogGenerator.generate(a, 30_000, 3, true);
        LogGenerator.generate(b, 30_000, 3, true);
        assertTrue(Arrays.equals(Files.readAllBytes(a), Files.readAllBytes(b)));
        Report reference = Analyzer.run(AnalysisConfig.builder(a).strategy("sequential").build()).report();
        assertEquals(0, reference.malformedLines());
        for (String strategy : new String[]{"parallel", "virtual"}) {
            assertEquals(reference, Analyzer.run(AnalysisConfig.builder(a).strategy(strategy).chunkBytes(100_000).build()).report());
        }
    }

    @Test
    void worldwideLogsPutKenyaOnTopAndShowManyCountries() throws Exception {
        Path file = dir.resolve("w.log");
        LogGenerator.generate(file, 200_000, 42, true);
        GeoReport g = Analyzer.run(AnalysisConfig.builder(file).strategy("parallel").build()).report().geo();
        assertTrue(g.available());
        assertEquals(g.loginAttempts(), g.locatedAttempts(), "every worldwide address can be placed");
        assertTrue(g.countriesSeen() >= 25, "countries seen: " + g.countriesSeen());
        assertEquals("KE", g.topCountries().get(0).code());
        assertEquals("Nairobi", g.topCountries().get(0).cities().get(0).city());
        assertTrue(g.topCountries().get(0).successes() > g.topCountries().get(0).failures(), "home logins mostly succeed");
        GeoReport.CountryLogins us = g.topCountries().stream().filter(c -> c.code().equals("US")).findFirst().orElseThrow();
        assertTrue(us.failures() > us.successes(), "logins from abroad mostly fail");
    }
}
