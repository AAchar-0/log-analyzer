package io.github.aachar0.loganalyzer.geo;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GeoDatabaseTest {

    @TempDir
    Path dir;

    private GeoDatabase build(String v4Csv, String v6Csv) throws IOException {
        Path in4 = dir.resolve("v4.csv");
        Path in6 = dir.resolve("v6.csv");
        Path out = dir.resolve("geo.bin.gz");
        Files.writeString(in4, v4Csv, StandardCharsets.UTF_8);
        Files.writeString(in6, v6Csv, StandardCharsets.UTF_8);
        GeoDbBuilder.main(new String[]{in4.toString(), in6.toString(), out.toString(), "2026-01"});
        try (InputStream in = Files.newInputStream(out)) {
            return GeoDatabase.read(in);
        }
    }

    private static long v4(String text) {
        IpParser p = new IpParser();
        p.parse(text);
        return p.value();
    }

    @Test
    void roundTripFindsBlocksHolesAndEdges() throws IOException {
        GeoDatabase db = build(
                "10.0.0.0,10.0.0.255,KE,Nairobi County,,Nairobi,,-1.29,36.82,\n"
                        + "10.0.1.0,10.0.1.255,KE,Nairobi County,,Nairobi,,-1.29,36.82,\n"          // merges with the block before
                        + "10.0.3.0,10.0.3.255,UG,Central Region,,\"Kampala, Central\",,0.3,32.5,\n" // a hole before it; quoted comma
                        + "10.0.4.0,10.0.4.9,ZZ,,,,,0,0,\n"                                          // unusable country: unknown
                        + "255.255.255.0,255.255.255.255,US,California,,Los Angeles,,34,-118,\n",
                "2001:db8::,2001:db8:0:ff:ffff:ffff:ffff:ffff,KE,Nairobi County,,Nairobi,,0,0,\n"
                        + "2a20::,2bff:ffff:ffff:ffff:ffff:ffff:ffff:ffff,CH,Fribourg,,Murten/Morat,,0,0,\n");

        int a = db.lookupV4(v4("10.0.0.7"));
        assertEquals("KE", db.countryCode(a));
        assertEquals("Nairobi", db.city(a));
        assertEquals("Nairobi County", db.region(a));
        assertEquals(a, db.lookupV4(v4("10.0.1.200")), "neighbouring identical blocks are one place");
        assertEquals(a, db.lookupV4(v4("10.0.0.0")));
        assertEquals(a, db.lookupV4(v4("10.0.1.255")));

        assertEquals(GeoDatabase.UNKNOWN, db.lookupV4(v4("10.0.2.1")), "a hole is unknown");
        assertEquals(GeoDatabase.UNKNOWN, db.lookupV4(v4("0.0.0.0")), "before the first block is unknown");
        assertEquals(GeoDatabase.UNKNOWN, db.lookupV4(v4("9.255.255.255")));

        int k = db.lookupV4(v4("10.0.3.77"));
        assertEquals("UG", db.countryCode(k));
        assertEquals("Kampala, Central", db.city(k));
        assertEquals(GeoDatabase.UNKNOWN, db.lookupV4(v4("10.0.4.5")), "country ZZ is unknown");
        assertEquals(GeoDatabase.UNKNOWN, db.lookupV4(v4("10.0.5.0")));

        assertEquals("US", db.countryCode(db.lookupV4(0xFFFF_FFFFL)), "the very last address works");
        assertEquals("US", db.countryCode(db.lookupV4(v4("255.255.255.0"))));
        assertEquals(GeoDatabase.UNKNOWN, db.lookupV4(v4("255.255.254.255")));

        IpParser p = new IpParser();
        p.parse("2001:db8:0:ff::1");
        assertEquals("KE", db.countryCode(db.lookupV6(p.value())));
        p.parse("2001:db8:0:100::1");
        assertEquals(GeoDatabase.UNKNOWN, db.lookupV6(p.value()));
        p.parse("2ad0:84b8:d5ac:c2bc::1");                    // inside the big short-start block
        assertEquals("CH", db.countryCode(db.lookupV6(p.value())));
        p.parse("3000::1");
        assertEquals(GeoDatabase.UNKNOWN, db.lookupV6(p.value()));
        assertEquals(GeoDatabase.UNKNOWN, db.lookupV6(-1L), "the very last IPv6 block is unknown here");
        assertTrue(db.source().contains("2026-01"));
        assertTrue(db.isLoaded());
    }

    @Test
    void overlappingRowsAreTrimmedInsteadOfBreakingTheTable() throws IOException {
        GeoDatabase db = build(
                "10.0.0.0,10.0.0.255,KE,A,,Nairobi,,0,0,\n"
                        + "10.0.0.100,10.0.0.200,UG,B,,Kampala,,0,0,\n"       // completely inside: ignored
                        + "10.0.0.200,10.0.1.255,TZ,C,,Dodoma,,0,0,\n",       // overlaps the end: trimmed to start at .1.0
                "");
        assertEquals("KE", db.countryCode(db.lookupV4(v4("10.0.0.150"))));
        assertEquals("KE", db.countryCode(db.lookupV4(v4("10.0.0.255"))));
        assertEquals("TZ", db.countryCode(db.lookupV4(v4("10.0.1.0"))));
        assertEquals("TZ", db.countryCode(db.lookupV4(v4("10.0.1.255"))));
        assertEquals(GeoDatabase.UNKNOWN, db.lookupV4(v4("10.0.2.0")));
    }

    @Test
    void anEmptyV6FileStillGivesAWorkingDatabase() throws IOException {
        GeoDatabase db = build("10.0.0.0,10.0.0.255,KE,A,,Nairobi,,0,0,\n", "");
        assertEquals(GeoDatabase.UNKNOWN, db.lookupV6(0x2001_0db8_0000_0000L));
        assertEquals("KE", db.countryCode(db.lookupV4(v4("10.0.0.1"))));
    }

    @Test
    void damagedFilesAreRejectedWithAClearErrorNotACrash() throws IOException {
        assertThrows(IOException.class, () -> GeoDatabase.read(new ByteArrayInputStream(new byte[]{1, 2, 3})));
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(bytes)) {
            gz.write(new byte[]{0, 0, 0, 1});                  // gzip fine, but the wrong magic number
        }
        assertThrows(IOException.class, () -> GeoDatabase.read(new ByteArrayInputStream(bytes.toByteArray())));

        GeoDatabase good = build("10.0.0.0,10.0.0.255,KE,A,,Nairobi,,0,0,\n", "");
        byte[] whole = Files.readAllBytes(dir.resolve("geo.bin.gz"));
        byte[] cut = java.util.Arrays.copyOf(whole, whole.length / 2);   // a truncated download
        assertThrows(IOException.class, () -> GeoDatabase.read(new ByteArrayInputStream(cut)));
        assertTrue(good.isLoaded());
    }

    @Test
    void theEmptyDatabaseKnowsNothingAndNeverThrows() {
        GeoDatabase empty = GeoDatabase.EMPTY;
        assertEquals(GeoDatabase.UNKNOWN, empty.lookupV4(123456789L));
        assertEquals(GeoDatabase.UNKNOWN, empty.lookupV6(123456789L));
        assertEquals("", empty.countryCode(5));
        assertEquals("", empty.city(-1));
        assertEquals(false, empty.isLoaded());
    }

    @Test
    void theShippedDatabaseLoadsAndKnowsWellKnownPlaces() {
        GeoDatabase db = GeoDatabase.get();
        assertTrue(db.isLoaded(), "the data file inside the program must load");
        assertTrue(db.locationCount() > 100_000);
        assertEquals("US", db.countryCode(db.lookupV4(v4("8.8.8.8"))));
        assertEquals(GeoDatabase.UNKNOWN, db.lookupV4(v4("192.0.2.7")), "documentation addresses have no location");
        assertEquals(GeoDatabase.UNKNOWN, db.lookupV4(v4("10.1.2.3")), "private addresses have no location");
        assertEquals("Kenya", GeoDatabase.countryName("KE"));
        assertEquals("Unknown", GeoDatabase.countryName(""));
    }
}
