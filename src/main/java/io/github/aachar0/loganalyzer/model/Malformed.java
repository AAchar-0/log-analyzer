package io.github.aachar0.loganalyzer.model;

/**
 * Marks a line that did not match the log format. It carries no data, so one shared instance is enough
 * (creating millions of identical objects would waste memory).
 */
public record Malformed() implements ParseResult {
    public static final Malformed INSTANCE = new Malformed();
}
