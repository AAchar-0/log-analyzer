package io.github.aachar0.loganalyzer;

import io.github.aachar0.loganalyzer.web.WebServer;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WebServerTest {

    private static final WebServer.Limits LIMITS = new WebServer.Limits(200_000, 5_000, 5_000, 2, 1);
    private static final WebServer.Links LINKS =
            new WebServer.Links("https://example.org/portfolio", "https://example.org/source", "");

    private static HttpResponse<String> send(WebServer server, String method, String path, byte[] body) throws Exception {
        HttpRequest.BodyPublisher publisher = body == null
                ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(body);
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + server.port() + path))
                .method(method, publisher).build();
        return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static WebServer start(WebServer.Links links) throws Exception {
        WebServer server = WebServer.create("127.0.0.1", 0, LIMITS, links);
        server.start();
        return server;
    }

    @Test
    void healthAndPageAreServed() throws Exception {
        WebServer server = start(LINKS);
        try {
            assertEquals("ok", send(server, "GET", "/health", null).body());
            HttpResponse<String> page = send(server, "GET", "/", null);
            assertEquals(200, page.statusCode());
            assertTrue(page.body().contains("Created by Anade Acharo"));
            assertTrue(page.body().contains("https://example.org/portfolio"));
            assertTrue(page.body().contains("https://example.org/source"));
            assertEquals("nosniff", page.headers().firstValue("X-Content-Type-Options").orElse(""));
            assertEquals(200, send(server, "GET", "/app.js", null).statusCode());
            assertEquals(200, send(server, "GET", "/style.css", null).statusCode());
            assertEquals(404, send(server, "GET", "/secret", null).statusCode());
        } finally {
            server.stop();
        }
    }

    @Test
    void footerLinksAreHtmlEscaped() throws Exception {
        WebServer server = start(new WebServer.Links("https://x.test/\"><script>alert(1)</script>", "https://y.test", ""));
        try {
            String body = send(server, "GET", "/", null).body();
            assertFalse(body.contains("<script>alert(1)</script>"));
            assertTrue(body.contains("&quot;&gt;&lt;script&gt;"));
        } finally {
            server.stop();
        }
    }

    @Test
    void sampleAnalysisWorksForEveryStrategy() throws Exception {
        WebServer server = start(LINKS);
        try {
            for (String strategy : new String[]{"sequential", "parallel", "virtual"}) {
                HttpResponse<String> r = send(server, "POST",
                        "/api/analyze?source=sample&lines=1000&top=3&strategy=" + strategy, null);
                assertEquals(200, r.statusCode());
                assertTrue(r.body().contains("\"requests\":1000"), r.body());
                assertTrue(r.body().contains("\"strategy\":\"" + strategy + "\""));
            }
        } finally {
            server.stop();
        }
    }

    @Test
    void uploadedLogIsAnalysed() throws Exception {
        WebServer server = start(LINKS);
        try {
            String log = "1.1.1.1 - - [01/Nov/2026:10:15:32 +0000] \"GET /api/x/5 HTTP/1.1\" 200 10 7\nnot a log line\n";
            HttpResponse<String> r = send(server, "POST", "/api/analyze?source=upload", log.getBytes());
            assertEquals(200, r.statusCode());
            assertTrue(r.body().contains("\"requests\":1"));
            assertTrue(r.body().contains("\"malformedLines\":1"));
        } finally {
            server.stop();
        }
    }

    @Test
    void badInputGetsClearErrors() throws Exception {
        WebServer server = start(LINKS);
        try {
            assertEquals(400, send(server, "POST", "/api/analyze?strategy=nope", null).statusCode());
            assertEquals(400, send(server, "POST", "/api/analyze?source=sample&lines=abc", null).statusCode());
            assertEquals(400, send(server, "POST", "/api/analyze?source=sample&lines=999999", null).statusCode());
            assertEquals(400, send(server, "POST", "/api/analyze?source=other", null).statusCode());
            assertEquals(400, send(server, "POST", "/api/analyze?source=upload", new byte[0]).statusCode());
            assertEquals(405, send(server, "GET", "/api/analyze", null).statusCode());
        } finally {
            server.stop();
        }
    }

    @Test
    void tooLargeUploadIsRefused() throws Exception {
        WebServer server = start(LINKS);
        try {
            byte[] big = new byte[(int) LIMITS.maxUploadBytes() + 1000];
            java.util.Arrays.fill(big, (byte) 'a');
            assertEquals(413, send(server, "POST", "/api/analyze?source=upload", big).statusCode());
        } finally {
            server.stop();
        }
    }

    @Test
    void benchmarkReportsIdenticalResults() throws Exception {
        WebServer server = start(LINKS);
        try {
            HttpResponse<String> r = send(server, "POST", "/api/benchmark?lines=2000&runs=1", null);
            assertEquals(200, r.statusCode());
            assertTrue(r.body().contains("\"identical\":true"), r.body());
        } finally {
            server.stop();
        }
    }
}
