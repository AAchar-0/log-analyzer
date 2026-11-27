package io.github.aachar0.loganalyzer.web;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GeoWebTest {

    private static final WebServer.Limits LIMITS = new WebServer.Limits(200_000, 20_000, 5_000, 2, 1, 1000);
    private static final WebServer.Links LINKS = new WebServer.Links("https://example.org/p", "https://example.org/s", "");

    private static HttpResponse<String> send(WebServer s, String method, String path, byte[] body, String... headers)
            throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + s.port() + path))
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(body));
        for (int i = 0; i + 1 < headers.length; i += 2) {
            b.header(headers[i], headers[i + 1]);
        }
        return HttpClient.newHttpClient().send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static WebServer start(WebServer.Limits limits, WebServer.Policy policy) throws Exception {
        WebServer server = WebServer.create("127.0.0.1", 0, limits, LINKS, policy);
        server.start();
        return server;
    }

    @Test
    void worldwideSampleShowsCountriesCitiesAndFlagsBlockedAreas() throws Exception {
        WebServer server = start(LIMITS, WebServer.Policy.none());
        try {
            HttpResponse<String> r = send(server, "POST",
                    "/api/analyze?source=sample&lines=20000&worldwide=true&blocked=ru,cn&strategy=parallel", null);
            assertEquals(200, r.statusCode(), r.body());
            String body = r.body();
            assertTrue(body.contains("\"geo\":{\"available\":true"), body);
            assertTrue(body.contains("\"blocked\":[\"CN\",\"RU\"]"), "codes are upper-cased and sorted");
            assertTrue(body.contains("\"code\":\"KE\""), "Kenya is the busiest market in the sample");
            assertTrue(body.contains("\"city\":\"Nairobi\""));
            assertTrue(body.contains("\"restricted\":true"));
            assertTrue(body.contains("\"bottomCountries\":[{"));
            assertEquals("application/json; charset=utf-8", r.headers().firstValue("Content-Type").orElse(""));
        } finally {
            server.stop();
        }
    }

    @Test
    void theDefaultSampleHasNoPlaceableAddresses() throws Exception {
        WebServer server = start(LIMITS, WebServer.Policy.none());
        try {
            HttpResponse<String> r = send(server, "POST", "/api/analyze?source=sample&lines=5000&strategy=sequential", null);
            assertEquals(200, r.statusCode());
            assertTrue(r.body().contains("\"locatedAttempts\":0"), "documentation addresses have no location");
            assertTrue(r.body().contains("\"topCountries\":[]"));
        } finally {
            server.stop();
        }
    }

    @Test
    void serverDefaultAreasApplyUnlessTheRequestOverridesThem() throws Exception {
        WebServer server = start(LIMITS, new WebServer.Policy(Set.of("RU"), Set.of()));
        try {
            String url = "/api/analyze?source=sample&lines=5000&worldwide=true";
            assertTrue(send(server, "POST", url, null).body().contains("\"blocked\":[\"RU\"]"));
            assertTrue(send(server, "POST", url + "&blocked=CN", null).body().contains("\"blocked\":[\"CN\"]"));
            assertTrue(send(server, "POST", url + "&blocked=", null).body().contains("\"policy\":{\"configured\":false"));
            assertTrue(send(server, "GET", "/api/config", null).body().contains("\"defaultBlocked\":[\"RU\"]"));
        } finally {
            server.stop();
        }
    }

    @Test
    void uploadedLoginsAreLocatedAndBadCountryListsAreRefused() throws Exception {
        WebServer server = start(LIMITS, WebServer.Policy.none());
        try {
            String log = "8.8.8.8 - - [01/Nov/2026:10:15:32 +0000] \"POST /api/auth/login HTTP/1.1\" 401 10 7\n";
            HttpResponse<String> r = send(server, "POST", "/api/analyze?source=upload&blocked=US", log.getBytes());
            assertEquals(200, r.statusCode(), r.body());
            assertTrue(r.body().contains("\"code\":\"US\""));
            assertTrue(r.body().contains("\"restricted\":{\"attempts\":1"));

            for (String bad : new String[]{"KEN", "K", "ZZ", "1", "RU;DROP", "%3Cscript%3E"}) {
                HttpResponse<String> e = send(server, "POST", "/api/analyze?source=sample&lines=1000&blocked=" + bad, null);
                assertEquals(400, e.statusCode(), bad);
                assertFalse(e.body().contains("<script>"));
            }
            String tooLong = "US,".repeat(500);
            assertEquals(400, send(server, "POST", "/api/analyze?source=sample&lines=1000&allowed=" + tooLong, null).statusCode());
        } finally {
            server.stop();
        }
    }

    @Test
    void securityHeadersAreOnEveryResponse() throws Exception {
        WebServer server = start(LIMITS, WebServer.Policy.none());
        try {
            for (String path : new String[]{"/", "/health", "/api/config", "/nope"}) {
                HttpResponse<String> r = send(server, "GET", path, null);
                assertEquals("DENY", r.headers().firstValue("X-Frame-Options").orElse(""), path);
                assertEquals("nosniff", r.headers().firstValue("X-Content-Type-Options").orElse(""), path);
                assertTrue(r.headers().firstValue("Permissions-Policy").orElse("").contains("geolocation=()"), path);
                assertTrue(r.headers().firstValue("Strict-Transport-Security").isPresent(), path);
                assertTrue(r.headers().firstValue("Content-Security-Policy").orElse("").contains("default-src 'self'"), path);
            }
            String page = send(server, "GET", "/", null).body();
            assertTrue(page.contains("IP Geolocation by DB-IP"), "the data licence requires this credit");
            assertTrue(page.contains("Created by Anade Acharo"));
        } finally {
            server.stop();
        }
    }

    @Test
    void aClientThatAsksTooOftenGetsTooManyRequestsAndCannotFakeItsIdentity() throws Exception {
        WebServer.Limits tight = new WebServer.Limits(200_000, 20_000, 5_000, 2, 1, 3);
        WebServer server = start(tight, WebServer.Policy.none());
        try {
            String url = "/api/analyze?source=sample&lines=1000&strategy=sequential";
            for (int i = 0; i < 3; i++) {
                assertEquals(200, send(server, "POST", url, null).statusCode());
            }
            HttpResponse<String> limited = send(server, "POST", url, null);
            assertEquals(429, limited.statusCode());
            assertEquals("60", limited.headers().firstValue("Retry-After").orElse(""));
            assertEquals(200, send(server, "GET", "/health", null).statusCode(), "cheap pages are not limited");
            assertEquals(429, send(server, "POST", "/api/benchmark?lines=2000&runs=1", null).statusCode(),
                    "benchmark shares the allowance");
        } finally {
            server.stop();
        }
    }

    @Test
    void forwardedForIsTrustedOnlyFromTheProxyAndOnlyItsLastEntry() throws Exception {
        WebServer.Limits tight = new WebServer.Limits(200_000, 20_000, 5_000, 2, 1, 2);
        WebServer server = start(tight, WebServer.Policy.none());       // the test client connects from 127.0.0.1: a "proxy"
        try {
            String url = "/api/analyze?source=sample&lines=1000&strategy=sequential";
            assertEquals(200, send(server, "POST", url, null, "X-Forwarded-For", "198.51.100.1").statusCode());
            assertEquals(200, send(server, "POST", url, null, "X-Forwarded-For", "evil, 198.51.100.1").statusCode());
            assertEquals(429, send(server, "POST", url, null, "X-Forwarded-For", "203.0.113.77, 198.51.100.1").statusCode(),
                    "a visitor cannot dodge the limit by writing other addresses first");
            assertEquals(200, send(server, "POST", url, null, "X-Forwarded-For", "198.51.100.2").statusCode(),
                    "a different client has its own allowance");
        } finally {
            server.stop();
        }
    }
}
