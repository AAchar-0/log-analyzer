package io.github.aachar0.loganalyzer.report;

import io.github.aachar0.loganalyzer.geo.GeoDatabase;
import io.github.aachar0.loganalyzer.stats.GeoCounts;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Where login attempts came from: the countries trying the most, the countries trying the least, the nearest cities
 * of each, and how many attempts came from areas the business does not deal in (treated as malicious).
 *
 * Made only of records, so two reports can be compared with equals() like the rest of {@link Report}. Every list has
 * a fixed tie-break order (by country code or city name), so the answer never depends on the order the workers
 * finished in.
 *
 * "Nearest city" is the closest city the location data knows for the address. It is an ESTIMATE, good for spotting
 * patterns, not for pointing at a person: VPN and mobile users show where their provider's server is.
 */
public record GeoReport(
        boolean available,
        String source,
        long loginAttempts,
        long locatedAttempts,
        long unknownAttempts,
        int countriesSeen,
        List<String> blockedCountries,
        List<String> allowedCountries,
        Restricted restricted,
        List<CountryLogins> topCountries,
        List<CountryLogins> bottomCountries,
        List<CountryLogins> restrictedCountries) {

    /** How many nearest cities are listed for each country. */
    public static final int CITIES_PER_COUNTRY = 3;

    /** Logins from areas the business does not deal in. Successes there are the most worrying: someone got in. */
    public record Restricted(long attempts, long successes, long failures, int countries) {
    }

    public record CountryLogins(String code, String name, long attempts, long successes, long failures,
                                boolean restricted, List<CityLogins> cities) {
    }

    public record CityLogins(String city, String region, long attempts) {
    }

    /** Share of located attempts that came from restricted areas, in percent. */
    public double restrictedPercent() {
        return locatedAttempts == 0 ? 0.0 : 100.0 * restricted.attempts() / locatedAttempts;
    }

    private static final class Agg {
        final String code;
        long attempts;
        long successes;
        long failures;
        final List<long[]> places = new ArrayList<>();      // {location, attempts}

        Agg(String code) {
            this.code = code;
        }
    }

    static GeoReport from(GeoCounts counts, ReportOptions options) {
        List<String> blocked = List.copyOf(options.blockedCountries());
        List<String> allowed = List.copyOf(options.allowedCountries());
        if (counts.attempts() == 0) {
            return new GeoReport(GeoDatabase.enabled(), "", 0, 0, 0, 0, blocked, allowed,
                    new Restricted(0, 0, 0, 0), List.of(), List.of(), List.of());
        }

        GeoDatabase db = GeoDatabase.get();
        Map<String, Agg> countries = new HashMap<>();
        long unknown = 0;
        for (Map.Entry<Integer, long[]> e : counts.byLocation().entrySet()) {
            int location = e.getKey();
            long[] c = e.getValue();
            String code = db.countryCode(location);
            if (code.isEmpty()) {
                unknown += c[0];                              // private, reserved or unlisted address, or not an IP at all
                continue;
            }
            Agg agg = countries.computeIfAbsent(code, Agg::new);
            agg.attempts += c[0];
            agg.successes += c[1];
            agg.failures += c[2];
            agg.places.add(new long[]{location, c[0]});
        }

        List<Agg> all = new ArrayList<>(countries.values());
        int topN = options.topN();

        List<Agg> byMost = all.stream()
                .sorted(Comparator.<Agg>comparingLong(a -> -a.attempts).thenComparing(a -> a.code))
                .toList();
        List<Agg> byLeast = all.stream()
                .sorted(Comparator.<Agg>comparingLong(a -> a.attempts).thenComparing(a -> a.code))
                .toList();
        List<Agg> restrictedList = byMost.stream().filter(a -> options.isRestricted(a.code)).toList();

        long rAttempts = 0;
        long rSuccesses = 0;
        long rFailures = 0;
        for (Agg a : restrictedList) {
            rAttempts += a.attempts;
            rSuccesses += a.successes;
            rFailures += a.failures;
        }

        return new GeoReport(db.isLoaded(), db.source(), counts.attempts(), counts.attempts() - unknown, unknown,
                all.size(), blocked, allowed,
                new Restricted(rAttempts, rSuccesses, rFailures, restrictedList.size()),
                describe(byMost, topN, db, options), describe(byLeast, topN, db, options),
                describe(restrictedList, topN, db, options));
    }

    private static List<CountryLogins> describe(List<Agg> ranked, int limit, GeoDatabase db, ReportOptions options) {
        List<CountryLogins> out = new ArrayList<>();
        for (int i = 0; i < Math.min(limit, ranked.size()); i++) {
            Agg a = ranked.get(i);
            List<CityLogins> cities = a.places.stream()
                    .map(p -> new CityLogins(db.city((int) p[0]), db.region((int) p[0]), p[1]))
                    .sorted(Comparator.comparingLong(CityLogins::attempts).reversed()
                            .thenComparing(CityLogins::city).thenComparing(CityLogins::region))
                    .limit(CITIES_PER_COUNTRY)
                    .toList();
            out.add(new CountryLogins(a.code, GeoDatabase.countryName(a.code), a.attempts, a.successes, a.failures,
                    options.isRestricted(a.code), cities));
        }
        return List.copyOf(out);
    }
}
