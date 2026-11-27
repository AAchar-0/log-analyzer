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
 * @param ipFamily    4 or 6 when the client address was a valid IP address, 0 when it was not (see IpParser)
 * @param ip          the IPv4 number, or the first 64 bits of an IPv6 address; meaningless when ipFamily is 0.
 *                    Only used to look up the country while counting; the address itself is never stored.
 */
public record LogEntry(long epochMinute, String method, String route, int status, long bytes, int millis,
                       int ipFamily, long ip) implements ParseResult {

    /** An entry with no usable client address (what every entry was before locations were added). */
    public LogEntry(long epochMinute, String method, String route, int status, long bytes, int millis) {
        this(epochMinute, method, route, status, bytes, millis, 0, 0L);
    }

    /** True for 5xx codes: the server failed. */
    public boolean isServerError() {
        return status >= 500;
    }

    /** True for 4xx codes: the client sent a bad or unauthorised request. */
    public boolean isClientError() {
        return status >= 400 && status < 500;
    }
}
