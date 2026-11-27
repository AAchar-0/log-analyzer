package io.github.aachar0.loganalyzer.report;

import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;

/**
 * @param topN              how many rows to show in each "top" list
 * @param minRouteHits      routes with fewer requests than this are left out of the "slowest" list,
 *                          because the average of 2 requests says very little
 * @param blockedCountries  two-letter codes of areas the business does NOT deal in: a login from there is
 *                          treated as malicious
 * @param allowedCountries  optional: when not empty, a login from any country NOT in this list is treated as
 *                          malicious too
 */
public record ReportOptions(int topN, int minRouteHits, Set<String> blockedCountries, Set<String> allowedCountries) {

    public ReportOptions {
        blockedCountries = frozen(blockedCountries);
        allowedCountries = frozen(allowedCountries);
    }

    /** Options without any area rules (what this record was before locations were added). */
    public ReportOptions(int topN, int minRouteHits) {
        this(topN, minRouteHits, Set.of(), Set.of());
    }

    public static ReportOptions defaults() {
        return new ReportOptions(10, 10);
    }

    /** True when at least one area rule is set. */
    public boolean policyConfigured() {
        return !blockedCountries.isEmpty() || !allowedCountries.isEmpty();
    }

    /** True when a login from this country must be treated as malicious under the area rules. */
    public boolean isRestricted(String countryCode) {
        if (blockedCountries.contains(countryCode)) {
            return true;
        }
        return !allowedCountries.isEmpty() && !allowedCountries.contains(countryCode);
    }

    /** A sorted, unchangeable copy, so two options with the same countries are equal and print in the same order. */
    private static Set<String> frozen(Set<String> codes) {
        return codes == null ? Set.of() : Collections.unmodifiableSet(new TreeSet<>(codes));
    }
}
