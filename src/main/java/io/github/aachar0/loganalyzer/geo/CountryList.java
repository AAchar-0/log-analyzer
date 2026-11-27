package io.github.aachar0.loganalyzer.geo;

import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;

/**
 * Reads a list of countries typed by a person, such as "ru, cn  KP", into a clean set of two-letter codes.
 *
 * This text arrives from the web page, the command line or an environment variable, so it is untrusted input:
 * the length is capped, every code must be two letters AND a real country code (a typo like "KEN" or "ZZ" gets a
 * clear error instead of silently doing nothing), and the result is an immutable, sorted set.
 */
public final class CountryList {

    /** Longest text accepted (about 300 codes). */
    public static final int MAX_TEXT_LENGTH = 1200;

    private static final Set<String> VALID = new HashSet<>();

    static {
        Collections.addAll(VALID, Locale.getISOCountries());
        VALID.add("XK");                                      // Kosovo: used by location data but not an ISO code
    }

    private CountryList() {
    }

    /** Parses codes separated by commas, semicolons or spaces. Blank or null gives an empty set. */
    public static Set<String> parse(String text) {
        if (text == null || text.isBlank()) {
            return Set.of();
        }
        if (text.length() > MAX_TEXT_LENGTH) {
            throw new IllegalArgumentException("The country list is too long (at most " + MAX_TEXT_LENGTH + " characters).");
        }
        Set<String> codes = new TreeSet<>();
        for (String part : text.split("[,;\\s]+")) {
            if (part.isEmpty()) {
                continue;
            }
            String code = part.toUpperCase(Locale.ROOT);
            if (!VALID.contains(code)) {
                throw new IllegalArgumentException("'" + sanitise(part) + "' is not a two-letter country code. Use codes like KE, US, GB.");
            }
            codes.add(code);
        }
        return Collections.unmodifiableSet(codes);
    }

    /** Reads an environment variable such as BLOCKED_COUNTRIES. A bad value stops the program with a clear message. */
    public static Set<String> fromEnvironment(String name) {
        try {
            return parse(System.getenv(name));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Environment variable " + name + ": " + e.getMessage());
        }
    }

    /** True for a code that exists in the country tables. */
    public static boolean isValid(String code) {
        return code != null && VALID.contains(code.toUpperCase(Locale.ROOT));
    }

    /** Keeps an error message short and printable: it may echo what a stranger typed. */
    private static String sanitise(String text) {
        String clean = text.replaceAll("[^\\x21-\\x7E]", "?");
        return clean.length() > 12 ? clean.substring(0, 12) + "..." : clean;
    }
}
