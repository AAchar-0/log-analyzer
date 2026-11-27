package io.github.aachar0.loganalyzer.geo;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Locale;
import java.util.zip.GZIPInputStream;

/**
 * Finds the country and the nearest known city of an IP address, completely OFFLINE.
 *
 * Why offline? The analyzer may look up millions of addresses. Asking a web service about each one would be slow,
 * rate-limited, and would send your customers' addresses to a third party. Here the whole table (about 40 MB in
 * memory) ships inside the program and a lookup is a handful of array reads.
 *
 * How it is stored: for each kind of address there are two parallel, sorted arrays. {@code starts[i]} is the first
 * address of a block and {@code locs[i]} says where that block is. A block lasts until the next one starts, and
 * blocks nobody knows about are stored as location 0 ("unknown"). So finding an address means "find the last block
 * that starts at or before it": a binary search. A 65,536-slot index on the first 16 bits narrows the search to a few
 * entries first, which makes a lookup roughly 5 steps instead of 21.
 *
 * A "location" is one number that stands for (country, region, city). Counting per location number instead of per
 * address means memory never grows with the size of the log, only with the number of different places seen.
 *
 * Data: IP to City Lite by DB-IP (https://db-ip.com), licensed CC BY 4.0, which requires the credit shown on the web
 * page. Locations are ESTIMATES: a visitor using a VPN or mobile network appears where the provider's server is.
 *
 * Thread safety: immutable after loading, so any number of workers can read it at the same time without locks.
 */
public final class GeoDatabase {

    /** Location number used for "no information about this address". */
    public static final int UNKNOWN = 0;

    static final String RESOURCE = "/geo/geo-ip.bin.gz";
    static final int MAGIC = 0x4C47454F;                      // "LGEO"
    static final int VERSION = 1;
    private static final int BUCKETS = 1 << 16;
    private static final int MAX_ENTRIES = 40_000_000;        // sanity limit against a damaged file
    private static final int BLOCK_BYTES = 1 << 20;

    /** A database that knows nothing; used when the real one is switched off or cannot be loaded. */
    static final GeoDatabase EMPTY = new GeoDatabase("No IP location data loaded", new String[0], new String[]{""},
            new short[1], new int[1], new int[1], new int[0], new int[0], new long[0], new int[0], false);

    private final String source;
    private final String[] countries;     // index -> two-letter code
    private final String[] strings;       // shared region and city names; [0] is ""
    private final short[] locCountry;     // location -> index into countries
    private final int[] locRegion;        // location -> index into strings
    private final int[] locCity;          // location -> index into strings
    private final int[] starts4;          // sorted; each value is (address XOR 0x80000000) so signed compare works
    private final int[] locs4;
    private final int[] bucket4;
    private final long[] starts6;         // sorted first 64 bits, XOR Long.MIN_VALUE
    private final int[] locs6;
    private final int[] bucket6;
    private final boolean loaded;

    GeoDatabase(String source, String[] countries, String[] strings, short[] locCountry, int[] locRegion,
                int[] locCity, int[] starts4, int[] locs4, long[] starts6, int[] locs6, boolean loaded) {
        this.source = source;
        this.countries = countries;
        this.strings = strings;
        this.locCountry = locCountry;
        this.locRegion = locRegion;
        this.locCity = locCity;
        this.starts4 = starts4;
        this.locs4 = locs4;
        this.starts6 = starts6;
        this.locs6 = locs6;
        this.loaded = loaded;
        this.bucket4 = buildBuckets4(starts4);
        this.bucket6 = buildBuckets6(starts6);
    }

    // ------------------------------------------------------------------ the shared instance

    private static final class Holder {
        // The JVM runs this exactly once, even if many workers ask at the same moment.
        static final GeoDatabase INSTANCE = loadDefault();
    }

    /** The shared database. Loaded on first use; if it cannot be loaded the analyzer still works (all unknown). */
    public static GeoDatabase get() {
        return Holder.INSTANCE;
    }

    /** True unless the lookup was switched off with GEO_ENABLED=false. */
    public static boolean enabled() {
        String value = System.getenv("GEO_ENABLED");
        return value == null || !value.trim().equalsIgnoreCase("false");
    }

    /** Starts loading in the background so the first request does not have to wait. Safe to call many times. */
    public static void preload() {
        Thread thread = new Thread(GeoDatabase::get, "geo-preload");
        thread.setDaemon(true);
        thread.start();
    }

    private static GeoDatabase loadDefault() {
        if (!enabled()) {
            System.err.println("IP location lookup is switched off (GEO_ENABLED=false).");
            return EMPTY;
        }
        try (InputStream in = GeoDatabase.class.getResourceAsStream(RESOURCE)) {
            if (in == null) {
                System.err.println("IP location data not found in the program (" + RESOURCE + "). Locations will be unknown.");
                return EMPTY;
            }
            long started = System.nanoTime();
            GeoDatabase db = read(in);
            System.err.printf(Locale.ROOT, "IP location data loaded in %d ms (%,d IPv4 and %,d IPv6 blocks).%n",
                    (System.nanoTime() - started) / 1_000_000, db.starts4.length, db.starts6.length);
            return db;
        } catch (IOException | RuntimeException e) {
            // Never let a bad data file stop the analyzer: log the reason and carry on without locations.
            System.err.println("IP location data could not be loaded (" + e + "). Locations will be unknown.");
            return EMPTY;
        }
    }

    // ------------------------------------------------------------------ lookups

    /** Location number for an IPv4 address given as 0..4294967295. 0 means unknown. */
    public int lookupV4(long ip) {
        int[] keys = starts4;
        if (keys.length == 0) {
            return UNKNOWN;
        }
        int key = (int) ip ^ 0x80000000;
        int b = (int) (ip >>> 16) & 0xFFFF;
        int lo = bucket4[b];
        int hi = bucket4[b + 1];
        while (lo < hi) {                                     // last entry whose start is <= key
            int mid = (lo + hi + 1) >>> 1;
            if (keys[mid] <= key) {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        return locs4[lo];
    }

    /** Location number for the first 64 bits of an IPv6 address. 0 means unknown. */
    public int lookupV6(long high64) {
        long[] keys = starts6;
        if (keys.length == 0) {
            return UNKNOWN;
        }
        long key = high64 ^ Long.MIN_VALUE;
        int b = (int) (high64 >>> 48);
        int lo = bucket6[b];
        int hi = bucket6[b + 1];
        while (lo < hi) {
            int mid = (lo + hi + 1) >>> 1;
            if (keys[mid] <= key) {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        return locs6[lo];
    }

    /** Looks up by the result of {@link IpParser}: family V4 or V6 and its value. */
    public int lookup(int family, long value) {
        return switch (family) {
            case IpParser.V4 -> lookupV4(value);
            case IpParser.V6 -> lookupV6(value);
            default -> UNKNOWN;
        };
    }

    // ------------------------------------------------------------------ describing a location

    /** Two-letter country code (upper case), or "" for an unknown location. */
    public String countryCode(int location) {
        return location <= 0 || location >= locCountry.length ? "" : countries[locCountry[location]];
    }

    /** Region, state or county of the location, or "" when the data has none. */
    public String region(int location) {
        return location <= 0 || location >= locRegion.length ? "" : strings[locRegion[location]];
    }

    /** City of the location, or "" when the data has none. */
    public String city(int location) {
        return location <= 0 || location >= locCity.length ? "" : strings[locCity[location]];
    }

    /** English country name for a two-letter code; falls back to the code itself. */
    public static String countryName(String code) {
        if (code == null || code.isEmpty()) {
            return "Unknown";
        }
        String name = new Locale.Builder().setRegion(code).build().getDisplayCountry(Locale.ENGLISH);
        return name == null || name.isBlank() ? code : name;
    }

    /** Credit line required by the data licence, plus the data version. */
    public String source() {
        return source;
    }

    /** False when no location data is available (switched off or failed to load). */
    public boolean isLoaded() {
        return loaded;
    }

    public int locationCount() {
        return locCountry.length - 1;
    }

    // ------------------------------------------------------------------ reading the file

    /** Reads the compact file format written by {@link GeoDbBuilder}. The stream must be the gzip-compressed data. */
    static GeoDatabase read(InputStream raw) throws IOException {
        try (DataInputStream in = new DataInputStream(new BufferedInputStream(new GZIPInputStream(raw, 1 << 16), 1 << 16))) {
            if (in.readInt() != MAGIC) {
                throw new IOException("not an IP location file");
            }
            int version = in.readUnsignedByte();
            if (version != VERSION) {
                throw new IOException("unsupported IP location file version " + version);
            }
            String source = in.readUTF();

            int countryCount = in.readUnsignedShort();
            String[] countries = new String[countryCount];
            for (int i = 0; i < countryCount; i++) {
                countries[i] = in.readUTF();
            }

            int stringCount = checkedCount(in.readInt());
            String[] strings = new String[stringCount];
            for (int i = 0; i < stringCount; i++) {
                strings[i] = in.readUTF();
            }

            int locationCount = checkedCount(in.readInt());
            short[] locCountry = new short[locationCount + 1];
            int[] locRegion = new int[locationCount + 1];
            int[] locCity = new int[locationCount + 1];
            for (int i = 1; i <= locationCount; i++) {
                int c = in.readUnsignedShort();
                int r = in.readInt();
                int city = in.readInt();
                if (c >= countryCount || r < 0 || r >= stringCount || city < 0 || city >= stringCount) {
                    throw new IOException("damaged location table");
                }
                locCountry[i] = (short) c;
                locRegion[i] = r;
                locCity[i] = city;
            }

            int n4 = checkedCount(in.readInt());
            int[] starts4 = readInts(in, n4);
            int[] locs4 = readInts(in, n4);
            int n6 = checkedCount(in.readInt());
            long[] starts6 = readLongs(in, n6);
            int[] locs6 = readInts(in, n6);

            verifySorted(starts4);
            verifySorted(starts6);
            verifyLocations(locs4, locationCount);
            verifyLocations(locs6, locationCount);
            if (n4 > 0 && starts4[0] != Integer.MIN_VALUE || n6 > 0 && starts6[0] != Long.MIN_VALUE) {
                throw new IOException("address table does not start at zero");
            }
            return new GeoDatabase(source, countries, strings, locCountry, locRegion, locCity,
                    starts4, locs4, starts6, locs6, true);
        }
    }

    private static int checkedCount(int n) throws IOException {
        if (n < 0 || n > MAX_ENTRIES) {
            throw new IOException("damaged IP location file (bad count " + n + ")");
        }
        return n;
    }

    private static void verifySorted(int[] keys) throws IOException {
        for (int i = 1; i < keys.length; i++) {
            if (keys[i] <= keys[i - 1]) {
                throw new IOException("damaged IPv4 table (not sorted)");
            }
        }
    }

    private static void verifySorted(long[] keys) throws IOException {
        for (int i = 1; i < keys.length; i++) {
            if (keys[i] <= keys[i - 1]) {
                throw new IOException("damaged IPv6 table (not sorted)");
            }
        }
    }

    private static void verifyLocations(int[] locs, int locationCount) throws IOException {
        for (int loc : locs) {
            if (loc < 0 || loc > locationCount) {
                throw new IOException("damaged table (bad location number)");
            }
        }
    }

    /** Reads n ints in 1 MB blocks so the temporary buffer stays small. */
    private static int[] readInts(DataInputStream in, int n) throws IOException {
        int[] out = new int[n];
        byte[] block = new byte[BLOCK_BYTES];
        int done = 0;
        while (done < n) {
            int count = Math.min(n - done, BLOCK_BYTES / 4);
            readFully(in, block, count * 4);
            ByteBuffer.wrap(block, 0, count * 4).asIntBuffer().get(out, done, count);
            done += count;
        }
        return out;
    }

    private static long[] readLongs(DataInputStream in, int n) throws IOException {
        long[] out = new long[n];
        byte[] block = new byte[BLOCK_BYTES];
        int done = 0;
        while (done < n) {
            int count = Math.min(n - done, BLOCK_BYTES / 8);
            readFully(in, block, count * 8);
            ByteBuffer.wrap(block, 0, count * 8).asLongBuffer().get(out, done, count);
            done += count;
        }
        return out;
    }

    private static void readFully(DataInputStream in, byte[] block, int length) throws IOException {
        try {
            in.readFully(block, 0, length);
        } catch (EOFException e) {
            throw new IOException("IP location file is cut short", e);
        }
    }

    // ------------------------------------------------------------------ first-16-bits indexes

    private static int[] buildBuckets4(int[] starts) {
        int[] bucket = new int[BUCKETS + 1];
        if (starts.length == 0) {
            return bucket;
        }
        int i = 0;
        for (int b = 0; b < BUCKETS; b++) {
            int limit = (b << 16) ^ 0x80000000;               // the first address of this bucket, in sorted form
            while (i + 1 < starts.length && starts[i + 1] <= limit) {
                i++;
            }
            bucket[b] = i;
        }
        bucket[BUCKETS] = starts.length - 1;
        return bucket;
    }

    private static int[] buildBuckets6(long[] starts) {
        int[] bucket = new int[BUCKETS + 1];
        if (starts.length == 0) {
            return bucket;
        }
        int i = 0;
        for (int b = 0; b < BUCKETS; b++) {
            long limit = ((long) b << 48) ^ Long.MIN_VALUE;
            while (i + 1 < starts.length && starts[i + 1] <= limit) {
                i++;
            }
            bucket[b] = i;
        }
        bucket[BUCKETS] = starts.length - 1;
        return bucket;
    }
}
