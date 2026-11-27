package io.github.aachar0.loganalyzer;

import io.github.aachar0.loganalyzer.engine.AnalysisConfig;
import io.github.aachar0.loganalyzer.engine.Analyzer;
import io.github.aachar0.loganalyzer.geo.GeoDatabase;
import io.github.aachar0.loganalyzer.geo.IpParser;
import io.github.aachar0.loganalyzer.report.GeoReport;
import io.github.aachar0.loganalyzer.report.JsonReport;
import io.github.aachar0.loganalyzer.report.Report;
import io.github.aachar0.loganalyzer.report.ReportOptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Builds a log with known login traffic and checks every number of the "login attempts by country" section.
 * The expected country of each address is taken from the shipped database itself, so these tests keep passing
 * when the location data is refreshed next month.
 */
class GeoLoginReportTest {

    /** address, successful logins, failed logins */
    private record Source(String ip, int ok, int failed) {
    }

    private static final List<Source> SOURCES = List.of(
            new Source("8.8.8.8", 5, 20),
            new Source("3.164.187.10", 40, 3),
            new Source("41.89.198.9", 12, 1),
            new Source("2.16.53.7", 7, 30),
            new Source("2.27.72.1", 2, 9),
            new Source("1.178.94.5", 3, 4),
            new Source("2.17.248.3", 6, 6));

    @TempDir
    Path dir;

    private Path log;
    private final GeoDatabase db = GeoDatabase.get();

    private static String line(String ip, String method, String path, int status) {
        return ip + " - - [01/Nov/2026:10:15:32 +0000] \"" + method + " " + path + " HTTP/1.1\" " + status + " 100 10\n";
    }

    private String countryOf(String ip) {
        IpParser p = new IpParser();
        int family = p.parse(ip);
        return db.countryCode(db.lookup(family, p.value()));
    }

    @BeforeEach
    void writeLog() throws Exception {
        assumeTrue(db.isLoaded());
        StringBuilder sb = new StringBuilder();
        for (Source s : SOURCES) {
            for (int i = 0; i < s.ok(); i++) {
                sb.append(line(s.ip(), "POST", "/api/auth/login", 200));
            }
            for (int i = 0; i < s.failed(); i++) {
                sb.append(line(s.ip(), "POST", "/api/auth/login", 401));
            }
            sb.append(line(s.ip(), "GET", "/api/products", 200));         // other traffic is not a login attempt
            sb.append(line(s.ip(), "GET", "/api/auth/login", 200));       // fetching the page is not an attempt
            sb.append(line(s.ip(), "POST", "/api/auth/register", 201));
        }
        // Attempts that cannot be placed: documentation address, private address, host name, "-", IPv6 documentation.
        sb.append(line("192.0.2.9", "POST", "/api/auth/login", 401));
        sb.append(line("10.1.2.3", "POST", "/api/auth/login", 200));
        sb.append(line("localhost", "POST", "/api/auth/login", 401));
        sb.append(line("-", "POST", "/api/auth/signin", 401));
        sb.append(line("2001:db8::1", "POST", "/api/auth/login/", 401));
        sb.append(line("8.8.8.8", "POST", "/api/auth/LOGIN?next=%2F", 200));      // upper case and a query string still count
        log = dir.resolve("geo.log");
        Files.writeString(log, sb.toString(), StandardCharsets.US_ASCII);
    }

    /** What the report must say, worked out here by simple loops instead of the program's own code. */
    private record Expected(long attempts, long unknown, Map<String, long[]> perCountry) {
    }

    private Expected expected() {
        Map<String, long[]> perCountry = new HashMap<>();                 // code -> {attempts, ok, failed}
        long attempts = 0;
        long unknown = 5;                                                 // the five unplaceable lines above
        for (Source s : SOURCES) {
            attempts += s.ok() + s.failed();
            String cc = countryOf(s.ip());
            if (cc.isEmpty()) {
                unknown += s.ok() + s.failed();
                continue;
            }
            long[] c = perCountry.computeIfAbsent(cc, k -> new long[3]);
            c[0] += s.ok() + s.failed();
            c[1] += s.ok();
            c[2] += s.failed();
        }
        // The extra upper-case login from 8.8.8.8 (success).
        attempts += 5 + 1;
        String google = countryOf("8.8.8.8");
        if (!google.isEmpty()) {
            long[] c = perCountry.get(google);
            c[0]++;
            c[1]++;
        } else {
            unknown++;
        }
        return new Expected(attempts, unknown, perCountry);
    }

    private Report analyse(String strategy, long chunk, ReportOptions options) throws Exception {
        return Analyzer.run(AnalysisConfig.builder(log).strategy(strategy).threads(4).chunkBytes(chunk)
                .topN(options.topN()).blockedCountries(options.blockedCountries())
                .allowedCountries(options.allowedCountries()).build()).report();
    }

    @Test
    void everyNumberInTheCountrySectionIsRight() throws Exception {
        Expected e = expected();
        assumeTrue(e.perCountry().size() >= 4, "the chosen addresses should cover several countries");
        GeoReport g = analyse("sequential", 1 << 20, new ReportOptions(10, 1)).geo();

        assertTrue(g.available());
        assertEquals(e.attempts(), g.loginAttempts());
        assertEquals(g.loginAttempts(), g.locatedAttempts() + g.unknownAttempts());
        assertEquals(e.unknown(), g.unknownAttempts());
        assertEquals(e.perCountry().size(), g.countriesSeen());

        List<Map.Entry<String, long[]>> byMost = new ArrayList<>(e.perCountry().entrySet());
        byMost.sort(Comparator.<Map.Entry<String, long[]>>comparingLong(x -> -x.getValue()[0]).thenComparing(Map.Entry::getKey));
        assertEquals(byMost.size(), g.topCountries().size());
        for (int i = 0; i < byMost.size(); i++) {
            GeoReport.CountryLogins c = g.topCountries().get(i);
            assertEquals(byMost.get(i).getKey(), c.code(), "top list position " + i);
            assertEquals(byMost.get(i).getValue()[0], c.attempts());
            assertEquals(byMost.get(i).getValue()[1], c.successes());
            assertEquals(byMost.get(i).getValue()[2], c.failures());
            assertFalse(c.restricted());
            assertFalse(c.cities().isEmpty());
        }
        // The bottom list is the same countries from the fewest attempts upward.
        List<String> bottomExpected = new ArrayList<>(byMost.stream().map(Map.Entry::getKey).toList());
        bottomExpected.sort(Comparator.<String>comparingLong(code -> e.perCountry().get(code)[0]).thenComparing(c -> c));
        assertEquals(bottomExpected, g.bottomCountries().stream().map(GeoReport.CountryLogins::code).toList());
        assertEquals(0, g.restricted().attempts());
        assertTrue(g.restrictedCountries().isEmpty());
    }

    @Test
    void theTopAndBottomListsAreCutToTheRequestedSize() throws Exception {
        Expected e = expected();
        assumeTrue(e.perCountry().size() >= 4);
        GeoReport g = analyse("sequential", 1 << 20, new ReportOptions(2, 1)).geo();
        assertEquals(2, g.topCountries().size());
        assertEquals(2, g.bottomCountries().size());
        assertTrue(g.topCountries().get(0).attempts() >= g.topCountries().get(1).attempts());
        assertTrue(g.bottomCountries().get(0).attempts() <= g.bottomCountries().get(1).attempts());
    }

    @Test
    void blockedAreasAreFlaggedAndCounted() throws Exception {
        Expected e = expected();
        assumeTrue(e.perCountry().size() >= 4);
        List<String> codes = new ArrayList<>(e.perCountry().keySet());
        codes.sort(String::compareTo);
        Set<String> blocked = new TreeSet<>(List.of(codes.get(0), codes.get(1)));
        GeoReport g = analyse("parallel", 1 << 20, new ReportOptions(10, 1, blocked, Set.of())).geo();

        long attempts = 0;
        long ok = 0;
        long failed = 0;
        for (String code : blocked) {
            attempts += e.perCountry().get(code)[0];
            ok += e.perCountry().get(code)[1];
            failed += e.perCountry().get(code)[2];
        }
        assertEquals(attempts, g.restricted().attempts());
        assertEquals(ok, g.restricted().successes());
        assertEquals(failed, g.restricted().failures());
        assertEquals(2, g.restricted().countries());
        assertEquals(blocked, new TreeSet<>(g.restrictedCountries().stream().map(GeoReport.CountryLogins::code).toList()));
        assertTrue(g.restrictedCountries().stream().allMatch(GeoReport.CountryLogins::restricted));
        assertTrue(g.topCountries().stream().filter(c -> !blocked.contains(c.code())).noneMatch(GeoReport.CountryLogins::restricted));
        assertEquals(100.0 * attempts / g.locatedAttempts(), g.restrictedPercent(), 1e-9);
    }

    @Test
    void anAllowListFlagsEverythingElse() throws Exception {
        Expected e = expected();
        assumeTrue(e.perCountry().size() >= 4);
        String keep = e.perCountry().keySet().stream().sorted().findFirst().orElseThrow();
        GeoReport g = analyse("virtual", 1 << 20, new ReportOptions(10, 1, Set.of(), Set.of(keep))).geo();
        long others = e.perCountry().entrySet().stream().filter(x -> !x.getKey().equals(keep)).mapToLong(x -> x.getValue()[0]).sum();
        assertEquals(others, g.restricted().attempts());
        assertEquals(e.perCountry().size() - 1, g.restricted().countries());
        assertTrue(g.topCountries().stream().filter(c -> c.code().equals(keep)).noneMatch(GeoReport.CountryLogins::restricted));
        // Blocking wins over allowing.
        GeoReport both = analyse("sequential", 1 << 20, new ReportOptions(10, 1, Set.of(keep), Set.of(keep))).geo();
        assertTrue(both.restrictedCountries().stream().anyMatch(c -> c.code().equals(keep)));
    }

    @Test
    void unplaceableAddressesAreCountedButNeverRankedOrFlagged() throws Exception {
        Expected e = expected();
        assumeTrue(e.perCountry().size() >= 4);
        GeoReport g = analyse("sequential", 1 << 20,
                new ReportOptions(50, 1, Set.of("US", "KE", "RU", "CN", "GB"), Set.of())).geo();
        assertTrue(g.unknownAttempts() >= 5);
        assertTrue(g.topCountries().stream().noneMatch(c -> c.code().isEmpty()));
        assertEquals(g.loginAttempts(), g.locatedAttempts() + g.unknownAttempts());
    }

    @Test
    void allStrategiesAndAnyChunkSizeGiveIdenticalReports() throws Exception {
        ReportOptions options = new ReportOptions(10, 1, Set.of("RU"), Set.of());
        Report reference = analyse("sequential", 1 << 20, options);
        assertTrue(reference.geo().loginAttempts() > 0);
        for (long chunk : new long[]{50, 333, 4096, 65_537, 1 << 20}) {
            for (String strategy : new String[]{"sequential", "parallel", "virtual"}) {
                assertEquals(reference, analyse(strategy, chunk, options), strategy + " with chunk " + chunk);
            }
        }
    }

    @Test
    void jsonCarriesTheSectionWithEscapedText() throws Exception {
        Expected e = expected();
        assumeTrue(e.perCountry().size() >= 4);
        Report r = analyse("sequential", 1 << 20, new ReportOptions(3, 1, Set.of("RU"), Set.of()));
        String json = JsonReport.report(r);
        assertTrue(json.contains("\"geo\":{\"available\":true"));
        assertTrue(json.contains("\"topCountries\":[{\"code\":\""));
        assertTrue(json.contains("\"nearestCities\":[{\"city\":\""));
        assertTrue(json.contains("\"policy\":{\"configured\":true,\"blocked\":[\"RU\"],\"allowed\":[]}"));
        assertTrue(json.contains("\"bottomCountries\":["));
        assertFalse(json.contains("<"));
        long openBraces = json.chars().filter(c -> c == '{').count();
        long closeBraces = json.chars().filter(c -> c == '}').count();
        assertEquals(openBraces, closeBraces, "balanced braces");
    }

    @Test
    void aLogWithoutLoginsHasAnEmptyButValidSection() throws Exception {
        Path none = dir.resolve("none.log");
        Files.writeString(none, line("8.8.8.8", "GET", "/api/products", 200), StandardCharsets.US_ASCII);
        GeoReport g = Analyzer.run(AnalysisConfig.builder(none).strategy("sequential").build()).report().geo();
        assertEquals(0, g.loginAttempts());
        assertTrue(g.topCountries().isEmpty());
        assertTrue(g.bottomCountries().isEmpty());
        assertEquals(0, g.restricted().attempts());
    }

    @Test
    void loginTrafficFromOneAddressIsCountedPerAttemptNotPerAddress() throws Exception {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 5000; i++) {
            sb.append(line("8.8.8.8", "POST", "/api/auth/login", 401));
        }
        Path flood = dir.resolve("flood.log");
        Files.writeString(flood, sb.toString(), StandardCharsets.US_ASCII);
        GeoReport g = Analyzer.run(AnalysisConfig.builder(flood).strategy("parallel").threads(3).chunkBytes(10_000).build())
                .report().geo();
        assertEquals(5000, g.loginAttempts());
        assertEquals(1, g.countriesSeen());
        assertEquals(5000, g.topCountries().get(0).attempts());
    }
}
