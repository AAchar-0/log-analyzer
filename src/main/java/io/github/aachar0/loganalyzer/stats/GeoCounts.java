package io.github.aachar0.loganalyzer.stats;

import io.github.aachar0.loganalyzer.geo.GeoDatabase;
import io.github.aachar0.loganalyzer.model.LogEntry;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Counts LOGIN attempts per place. Like everything in LogStats it belongs to one worker at a time (no locks) and
 * is combined with {@link #merge(GeoCounts)} when workers finish.
 *
 * Memory: the key is a "location number" (one number for country + region + city), NOT the IP address. A log with a
 * billion login attempts from a billion different addresses still needs only one small counter per place seen
 * (at most about 190,000), and no address is ever kept. That is what keeps this safe for the hardest data and for
 * privacy.
 *
 * Speed: each worker remembers its most recent addresses in a tiny direct-mapped cache, so an attacker who
 * hammers the login with the same few addresses costs one array read per line instead of a database search.
 */
public final class GeoCounts {

    private static final int CACHE_SIZE = 1024;               // must be a power of two

    private long attempts;                                    // every login attempt, located or not
    private final Map<Integer, long[]> byLocation = new HashMap<>();   // location -> {attempts, successes, failures}

    private GeoDatabase db;
    private byte[] cacheFamily;                               // 0 = empty slot
    private long[] cacheIp;
    private int[] cacheLocation;
    private int lastLocation = -1;
    private long[] lastCounters;

    /** Counts one login attempt. Success = 2xx/3xx, failure = 4xx (wrong password, blocked, rate-limited). */
    void recordLogin(LogEntry e) {
        attempts++;
        int location = locate(e.ipFamily(), e.ip());
        long[] counters;
        if (location == lastLocation) {                       // same place as the previous attempt: skip the map
            counters = lastCounters;
        } else {
            counters = byLocation.computeIfAbsent(location, k -> new long[3]);
            lastLocation = location;
            lastCounters = counters;
        }
        counters[0]++;
        int status = e.status();
        if (status >= 200 && status < 400) {
            counters[1]++;
        } else if (status >= 400 && status < 500) {
            counters[2]++;
        }
    }

    private int locate(int family, long ip) {
        if (family == 0) {
            return GeoDatabase.UNKNOWN;
        }
        if (db == null) {
            db = GeoDatabase.get();                           // first login line: loads the data if needed (once per JVM)
            cacheFamily = new byte[CACHE_SIZE];
            cacheIp = new long[CACHE_SIZE];
            cacheLocation = new int[CACHE_SIZE];
        }
        int slot = (int) ((ip * 0x9E3779B97F4A7C15L) >>> 54) & (CACHE_SIZE - 1);
        if (cacheFamily[slot] == family && cacheIp[slot] == ip) {
            return cacheLocation[slot];
        }
        int location = db.lookup(family, ip);
        cacheFamily[slot] = (byte) family;
        cacheIp[slot] = ip;
        cacheLocation[slot] = location;
        return location;
    }

    /** Adds everything counted by another GeoCounts into this one. */
    void merge(GeoCounts other) {
        attempts += other.attempts;
        other.byLocation.forEach((location, c) -> {
            long[] mine = byLocation.computeIfAbsent(location, k -> new long[3]);
            mine[0] += c[0];
            mine[1] += c[1];
            mine[2] += c[2];
        });
        lastLocation = -1;                                    // the cached counters may no longer be the map's own
        lastCounters = null;
    }

    /** All login attempts seen, including those whose address could not be placed. */
    public long attempts() {
        return attempts;
    }

    /** Read-only view: location number -> {attempts, successes, failures}. Location 0 means "unknown". */
    public Map<Integer, long[]> byLocation() {
        return Collections.unmodifiableMap(byLocation);
    }
}
