package io.github.aachar0.loganalyzer.model;

/**
 * One successfully parsed request line.
 *
 * A record is a short way to write an immutable data class: Java generates the constructor,
 * getters (named like the fields, e.g. entry.status()), equals, hashCode and toString.
 *
 * @param epochMinute whole minutes since 1970-01-01T00:00Z (the time, cut to the minute, in UTC)
 * @param method      HTTP method, for example GET
 * @param route       the path without the query string, numbers replaced by {id}, e.g. /api/products/{id}
 * @param status      HTTP status code, 100 to 599
 * @param bytes       size of the response body in bytes (0 when the log has "-")
 * @param millis      time the server took to answer, in milliseconds
 */
public record LogEntry(long epochMinute, String method, String route, int status, long bytes, int millis)
        implements ParseResult {

    /** True for 5xx codes: the server failed. */
    public boolean isServerError() {
        return status >= 500;
    }

    /** True for 4xx codes: the client sent a bad or unauthorised request. */
    public boolean isClientError() {
        return status >= 400 && status < 500;
    }
}
