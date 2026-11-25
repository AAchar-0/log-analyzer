package io.github.aachar0.loganalyzer.model;

/**
 * The outcome of parsing ONE log line: either a good {@link LogEntry} or a {@link Malformed} marker.
 *
 * "sealed" means only the two listed types can ever implement this interface. The compiler therefore
 * knows every possible case and forces a switch over a ParseResult to handle both (no "default" needed).
 */
public sealed interface ParseResult permits LogEntry, Malformed {
}
