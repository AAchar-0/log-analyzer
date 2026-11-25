package io.github.aachar0.loganalyzer.parse;

/** Unit of the last number on each log line. Some servers log microseconds instead of milliseconds. */
public enum ResponseTimeUnit {
    MILLIS(1),
    MICROS(1000);

    private final long divisor;

    ResponseTimeUnit(long divisor) {
        this.divisor = divisor;
    }

    /** Converts a logged value into whole milliseconds. */
    public long toMillis(long logged) {
        return logged / divisor;
    }

    /** Reads "ms" or "us" (case-insensitive) from the command line or the web request. */
    public static ResponseTimeUnit fromText(String text) {
        return switch (text.toLowerCase(java.util.Locale.ROOT)) {
            case "ms", "millis" -> MILLIS;
            case "us", "micros" -> MICROS;
            default -> throw new IllegalArgumentException("Time unit must be ms or us, got: " + text);
        };
    }
}
