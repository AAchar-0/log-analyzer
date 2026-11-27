package io.github.aachar0.loganalyzer.geo;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * Developer tool (not used while the app runs): converts the free "IP to City Lite" CSV files from DB-IP into the
 * compact file that {@link GeoDatabase} loads. Run it once a month to refresh the data:
 *
 * <pre>
 * java -cp target/classes io.github.aachar0.loganalyzer.geo.GeoDbBuilder \
 *      dbip-city-ipv4.csv.gz dbip-city-ipv6.csv.gz src/main/resources/geo/geo-ip.bin.gz 2026-11
 * </pre>
 *
 * Each CSV line looks like: start,end,country,region,region2,city,postcode,latitude,longitude,timezone
 *
 * What it does to keep the file small and the lookups fast:
 *  - neighbouring blocks that belong to the same place are merged into one;
 *  - holes between blocks are written as location 0 ("unknown"), so a lookup never needs an "end" value;
 *  - every different (country, region, city) gets one number, and the names are stored only once.
 */
public final class GeoDbBuilder {

    private final List<String> countries = new ArrayList<>();
    private final Map<String, Integer> countryIndex = new HashMap<>();
    private final List<String> strings = new ArrayList<>(List.of(""));
    private final Map<String, Integer> stringIndex = new HashMap<>(Map.of("", 0));
    private final List<int[]> locations = new ArrayList<>();           // {countryIdx, regionStr, cityStr}
    private final Map<String, Integer> locationIndex = new HashMap<>();
    private final IpParser ip = new IpParser();

    /** Growing arrays of (start, location) pairs for one address family. */
    static final class Table {
        long[] starts = new long[1 << 16];
        int[] locs = new int[1 << 16];
        int size;
        long rows;

        void emit(long start, int loc) {
            if (size > 0 && locs[size - 1] == loc) {
                return;                                                // same place as the block before: merge
            }
            if (size == starts.length) {
                starts = Arrays.copyOf(starts, size * 2);
                locs = Arrays.copyOf(locs, size * 2);
            }
            starts[size] = start;
            locs[size++] = loc;
        }
    }

    public static void main(String[] args) throws IOException {
        if (args.length != 4) {
            System.err.println("Usage: GeoDbBuilder <ipv4.csv.gz> <ipv6.csv.gz> <output.bin.gz> <data-month e.g. 2026-11>");
            System.exit(2);
        }
        String source = "IP Geolocation by DB-IP (https://db-ip.com), IP to City Lite, " + args[3];
        GeoDbBuilder builder = new GeoDbBuilder();
        Table t4 = builder.readCsv(Path.of(args[0]), false);
        Table t6 = builder.readCsv(Path.of(args[1]), true);
        builder.write(Path.of(args[2]), source, t4, t6);
        System.out.printf(Locale.ROOT, "Wrote %s: %,d IPv4 blocks (from %,d rows), %,d IPv6 blocks (from %,d rows), "
                        + "%,d places, %,d names, %d countries, %.1f MB%n",
                args[2], t4.size, t4.rows, t6.size, t6.rows, builder.locations.size(), builder.strings.size(),
                builder.countries.size(), Files.size(Path.of(args[2])) / 1_000_000.0);
    }

    /** Reads one CSV file (plain or .gz) into a table. Rows must be sorted by address; overlaps are trimmed. */
    Table readCsv(Path file, boolean v6) throws IOException {
        Table table = new Table();
        long nextExpected = 0;                                         // first address not yet covered (unsigned)
        boolean reachedEnd = false;
        long maxKey = v6 ? -1L : 0xFFFF_FFFFL;

        try (InputStream raw = Files.newInputStream(file);
             InputStream in = file.toString().endsWith(".gz") ? new GZIPInputStream(raw, 1 << 16) : raw;
             BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8), 1 << 16)) {
            String line;
            while ((line = reader.readLine()) != null && !reachedEnd) {
                if (line.isBlank()) {
                    continue;
                }
                String[] f = splitCsv(line);
                if (f.length < 6) {
                    continue;
                }
                long start = parseKey(f[0], v6);
                long end = parseKey(f[1], v6);
                if (start == Long.MIN_VALUE || end == Long.MIN_VALUE || Long.compareUnsigned(end, start) < 0) {
                    continue;                                          // not an address of the expected kind
                }
                table.rows++;
                if (Long.compareUnsigned(start, nextExpected) < 0) {   // overlaps what is already covered: trim
                    if (Long.compareUnsigned(end, nextExpected) < 0) {
                        continue;
                    }
                    start = nextExpected;
                }
                if (Long.compareUnsigned(start, nextExpected) > 0) {
                    table.emit(nextExpected, GeoDatabase.UNKNOWN);     // a hole (or the space before the first block)
                }
                table.emit(start, locationFor(f[2], f[3], f[5]));
                if (end == maxKey) {
                    reachedEnd = true;
                } else {
                    nextExpected = end + 1;
                }
            }
        }
        if (table.size == 0) {
            table.emit(0, GeoDatabase.UNKNOWN);
        } else if (!reachedEnd) {
            table.emit(nextExpected, GeoDatabase.UNKNOWN);             // everything after the last block is unknown
        }
        return table;
    }

    /** IPv4: the address as a number. IPv6: the first 64 bits. Long.MIN_VALUE marks "not an address of this kind". */
    private long parseKey(String text, boolean v6) {
        int family = ip.parse(text);
        if (v6) {
            if (family == IpParser.V6) {
                return ip.value();
            }
            return Long.MIN_VALUE;
        }
        return family == IpParser.V4 ? ip.value() : Long.MIN_VALUE;
    }

    private int locationFor(String country, String region, String city) {
        String code = country.trim().toUpperCase(Locale.ROOT);
        if (code.length() != 2 || !Character.isLetter(code.charAt(0)) || !Character.isLetter(code.charAt(1))
                || code.equals("ZZ")) {
            return GeoDatabase.UNKNOWN;
        }
        int c = countryIndex.computeIfAbsent(code, k -> {
            countries.add(k);
            return countries.size() - 1;
        });
        int r = stringId(clean(region));
        int cityId = stringId(clean(city));
        String key = c + "|" + r + "|" + cityId;
        Integer existing = locationIndex.get(key);
        if (existing != null) {
            return existing;
        }
        locations.add(new int[]{c, r, cityId});
        int id = locations.size();                                     // location numbers start at 1
        locationIndex.put(key, id);
        return id;
    }

    private int stringId(String s) {
        return stringIndex.computeIfAbsent(s, k -> {
            strings.add(k);
            return strings.size() - 1;
        });
    }

    private static String clean(String s) {
        String t = s.trim();
        return t.length() > 100 ? t.substring(0, 100) : t;
    }

    /** Splits one CSV line; understands "quoted, values" and doubled quotes. */
    static String[] splitCsv(String line) {
        List<String> out = new ArrayList<>(12);
        StringBuilder sb = new StringBuilder();
        boolean quoted = false;
        for (int i = 0; i < line.length(); i++) {
            char ch = line.charAt(i);
            if (quoted) {
                if (ch == '"') {
                    if (i + 1 < line.length() && line.charAt(i + 1) == '"') {
                        sb.append('"');
                        i++;
                    } else {
                        quoted = false;
                    }
                } else {
                    sb.append(ch);
                }
            } else if (ch == '"') {
                quoted = true;
            } else if (ch == ',') {
                out.add(sb.toString());
                sb.setLength(0);
            } else {
                sb.append(ch);
            }
        }
        out.add(sb.toString());
        return out.toArray(new String[0]);
    }

    private void write(Path target, String source, Table t4, Table t6) throws IOException {
        if (target.getParent() != null) {
            Files.createDirectories(target.getParent());
        }
        try (OutputStream file = Files.newOutputStream(target);
             DataOutputStream out = new DataOutputStream(new GZIPOutputStream(file, 1 << 16) {
                 {
                     def.setLevel(9);
                 }
             })) {
            out.writeInt(GeoDatabase.MAGIC);
            out.writeByte(GeoDatabase.VERSION);
            out.writeUTF(source);
            out.writeShort(countries.size());
            for (String c : countries) {
                out.writeUTF(c);
            }
            out.writeInt(strings.size());
            for (String s : strings) {
                out.writeUTF(s);
            }
            out.writeInt(locations.size());
            for (int[] l : locations) {
                out.writeShort(l[0]);
                out.writeInt(l[1]);
                out.writeInt(l[2]);
            }

            out.writeInt(t4.size);
            int[] keys4 = new int[t4.size];
            for (int i = 0; i < t4.size; i++) {
                keys4[i] = (int) t4.starts[i] ^ 0x80000000;            // flipped so signed comparison sorts correctly
            }
            writeInts(out, keys4, t4.size);
            writeInts(out, t4.locs, t4.size);

            out.writeInt(t6.size);
            long[] keys6 = new long[t6.size];
            for (int i = 0; i < t6.size; i++) {
                keys6[i] = t6.starts[i] ^ Long.MIN_VALUE;
            }
            writeLongs(out, keys6, t6.size);
            writeInts(out, t6.locs, t6.size);
        }
    }

    private static void writeInts(DataOutputStream out, int[] values, int n) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(1 << 20);
        for (int done = 0; done < n; ) {
            int count = Math.min(n - done, buffer.capacity() / 4);
            buffer.clear();
            buffer.asIntBuffer().put(values, done, count);
            out.write(buffer.array(), 0, count * 4);
            done += count;
        }
    }

    private static void writeLongs(DataOutputStream out, long[] values, int n) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(1 << 20);
        for (int done = 0; done < n; ) {
            int count = Math.min(n - done, buffer.capacity() / 8);
            buffer.clear();
            buffer.asLongBuffer().put(values, done, count);
            out.write(buffer.array(), 0, count * 8);
            done += count;
        }
    }
}
