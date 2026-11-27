package io.github.aachar0.loganalyzer.web;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.github.aachar0.loganalyzer.engine.AnalysisConfig;
import io.github.aachar0.loganalyzer.engine.AnalysisResult;
import io.github.aachar0.loganalyzer.engine.Analyzer;
import io.github.aachar0.loganalyzer.engine.Benchmark;
import io.github.aachar0.loganalyzer.gen.LogGenerator;
import io.github.aachar0.loganalyzer.geo.CountryList;
import io.github.aachar0.loganalyzer.geo.GeoDatabase;
import io.github.aachar0.loganalyzer.geo.IpParser;
import io.github.aachar0.loganalyzer.parse.ResponseTimeUnit;
import io.github.aachar0.loganalyzer.report.JsonReport;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.Year;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;

/**
 * The web app, built on the HTTP server that ships inside the JDK (no framework, nothing to download).
 *
 * Routes
 *   GET  /               the page          GET /app.js, /style.css   its files
 *   GET  /health         "ok" (used by the hosting platform)
 *   GET  /api/config     limits of this server
 *   POST /api/analyze    source=sample|upload, strategy, lines, seed, top, unit,
 *                        blocked=RU,CN (areas you do not deal in), allowed=KE,UG (optional), worldwide=true (sample only)
 *   POST /api/benchmark  lines, runs
 *
 * Built for a public demo, so it defends itself:
 *   - upload size is capped and checked while streaming (not only by the Content-Length header);
 *   - sample and benchmark sizes are capped;
 *   - only a few analyses run at once, the others get "429 try again";
 *   - uploaded and generated files live in the temp folder and are deleted right after use;
 *   - the browser page builds its tables with textContent, so text from a log can never become HTML;
 *   - client addresses are never logged (nor kept: login attempts are counted per place, not per address);
 *   - each client may start only a limited number of analyses per minute;
 *   - country lists typed by visitors are validated (two-letter codes, length capped).
 */
public final class WebServer {

    /** Size limits. Free hosting has little memory and CPU, so the defaults are modest; raise them with environment variables. */
    public record Limits(long maxUploadBytes, long maxSampleLines, long maxBenchmarkLines,
                         int maxBenchmarkRuns, int maxConcurrent, int maxRequestsPerMinute) {

        /** Same limits as before, with the default request rate per client. */
        public Limits(long maxUploadBytes, long maxSampleLines, long maxBenchmarkLines, int maxBenchmarkRuns,
                      int maxConcurrent) {
            this(maxUploadBytes, maxSampleLines, maxBenchmarkLines, maxBenchmarkRuns, maxConcurrent, 30);
        }

        public static Limits defaults() {
            return new Limits(25L * 1024 * 1024, 1_000_000, 300_000, 5, 1, 30);
        }

        public static Limits fromEnvironment() {
            Limits d = defaults();
            return new Limits(
                    envLong("MAX_UPLOAD_MB", d.maxUploadBytes() / (1024 * 1024)) * 1024 * 1024,
                    envLong("MAX_SAMPLE_LINES", d.maxSampleLines()),
                    envLong("MAX_BENCHMARK_LINES", d.maxBenchmarkLines()),
                    (int) envLong("MAX_BENCHMARK_RUNS", d.maxBenchmarkRuns()),
                    (int) envLong("MAX_CONCURRENT", d.maxConcurrent()),
                    (int) envLong("MAX_REQUESTS_PER_MINUTE", d.maxRequestsPerMinute()));
        }

        private static long envLong(String name, long fallback) {
            String value = System.getenv(name);
            if (value == null || value.isBlank()) {
                return fallback;
            }
            try {
                return Long.parseLong(value.trim());
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Environment variable " + name + " must be a whole number");
            }
        }
    }

    /** Links shown in the page footer, plus an optional website allowed to call the API from a browser (CORS). */
    public record Links(String portfolioUrl, String sourceUrl, String allowedOrigin) {

        public static Links fromEnvironment() {
            return new Links(
                    env("PORTFOLIO_URL", "https://aachar-0.github.io/"),
                    env("SOURCE_URL", "https://github.com/AAchar-0/log-analyzer"),
                    env("ALLOWED_ORIGIN", ""));
        }

        private static String env(String name, String fallback) {
            String value = System.getenv(name);
            return value == null || value.isBlank() ? fallback : value.trim();
        }
    }

    /**
     * The default areas for logins: BLOCKED_COUNTRIES (areas the business does not deal in) and optionally
     * ALLOWED_COUNTRIES. A visitor can override both for one analysis with the blocked and allowed parameters.
     */
    public record Policy(Set<String> blocked, Set<String> allowed) {

        public static Policy none() {
            return new Policy(Set.of(), Set.of());
        }

        public static Policy fromEnvironment() {
            return new Policy(CountryList.fromEnvironment("BLOCKED_COUNTRIES"), CountryList.fromEnvironment("ALLOWED_COUNTRIES"));
        }
    }

    /** An error that should reach the visitor as a clear message with a specific HTTP status. */
    private static final class ApiException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        private final int status;

        ApiException(int status, String message) {
            super(message);
            this.status = status;
        }
    }

    private static final DateTimeFormatter LOG_STAMP =
            DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH).withZone(ZoneOffset.UTC);

    private final HttpServer server;
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
    private final Limits limits;
    private final Links links;
    private final Policy policy;
    private final RateLimiter rateLimiter;
    private final Semaphore analysisSlots;
    private final Semaphore uploadSlots = new Semaphore(4);
    private final String indexTemplate;
    private final byte[] appJs;
    private final byte[] styleCss;

    private WebServer(HttpServer server, Limits limits, Links links, Policy policy) throws IOException {
        this.server = server;
        this.limits = limits;
        this.links = links;
        this.policy = policy;
        this.rateLimiter = new RateLimiter(limits.maxRequestsPerMinute());
        this.analysisSlots = new Semaphore(Math.max(1, limits.maxConcurrent()));
        this.indexTemplate = new String(resource("index.html"), StandardCharsets.UTF_8);
        this.appJs = resource("app.js");
        this.styleCss = resource("style.css");
        server.setExecutor(executor);                       // one cheap virtual thread per request
        server.createContext("/", this::handle);
    }

    /** Default areas come from the BLOCKED_COUNTRIES and ALLOWED_COUNTRIES environment variables. */
    public static WebServer create(String host, int port, Limits limits, Links links) throws IOException {
        return create(host, port, limits, links, Policy.fromEnvironment());
    }

    public static WebServer create(String host, int port, Limits limits, Links links, Policy policy) throws IOException {
        return new WebServer(HttpServer.create(new InetSocketAddress(host, port), 0), limits, links, policy);
    }

    public void start() {
        server.start();
        if (GeoDatabase.enabled()) {
            GeoDatabase.preload();                          // load the location data in the background, off the request path
        }
    }

    /** The port actually used (useful when created with port 0 in tests). */
    public int port() {
        return server.getAddress().getPort();
    }

    public void stop() {
        server.stop(0);
        executor.shutdownNow();
    }

    // ------------------------------------------------------------------ request handling

    private void handle(HttpExchange ex) throws IOException {
        long started = System.nanoTime();
        int status = 500;
        try {
            status = route(ex);
        } catch (ApiException e) {
            status = e.status;
            sendJson(ex, e.status, "{\"error\":" + JsonReport.quote(e.getMessage()) + "}");
        } catch (Exception e) {
            // Details go to the server log only. The visitor gets a generic message (no stack traces in public).
            System.err.println("Request failed: " + e);
            status = 500;
            sendJson(ex, 500, "{\"error\":\"Something went wrong on the server.\"}");
        } finally {
            logAccess(ex, status, (System.nanoTime() - started) / 1_000_000);
            ex.close();
        }
    }

    private int route(HttpExchange ex) throws Exception {
        String method = ex.getRequestMethod();
        String path = ex.getRequestURI().getPath();
        boolean api = path.startsWith("/api/");

        if (api && method.equals("OPTIONS")) {              // CORS pre-flight, only meaningful when an origin is allowed
            applyHeaders(ex, true);
            ex.sendResponseHeaders(204, -1);
            return 204;
        }
        switch (path) {
            case "/", "/index.html" -> {
                requireMethod(method, "GET");
                String html = indexTemplate
                        .replace("{{PORTFOLIO_URL}}", escapeHtml(links.portfolioUrl()))
                        .replace("{{SOURCE_URL}}", escapeHtml(links.sourceUrl()))
                        .replace("{{YEAR}}", String.valueOf(Year.now().getValue()));
                return sendBytes(ex, 200, "text/html; charset=utf-8", html.getBytes(StandardCharsets.UTF_8), false);
            }
            case "/app.js" -> {
                requireMethod(method, "GET");
                return sendBytes(ex, 200, "text/javascript; charset=utf-8", appJs, false);
            }
            case "/style.css" -> {
                requireMethod(method, "GET");
                return sendBytes(ex, 200, "text/css; charset=utf-8", styleCss, false);
            }
            case "/health" -> {
                requireMethod(method, "GET");
                return sendBytes(ex, 200, "text/plain; charset=utf-8", "ok".getBytes(StandardCharsets.UTF_8), false);
            }
            case "/api/config" -> {
                requireMethod(method, "GET");
                return sendJson(ex, 200, "{\"maxUploadMb\":" + limits.maxUploadBytes() / (1024 * 1024)
                        + ",\"maxSampleLines\":" + limits.maxSampleLines()
                        + ",\"maxBenchmarkLines\":" + limits.maxBenchmarkLines()
                        + ",\"maxBenchmarkRuns\":" + limits.maxBenchmarkRuns()
                        + ",\"cores\":" + Runtime.getRuntime().availableProcessors()
                        + ",\"java\":" + Runtime.version().feature()
                        + ",\"geo\":" + GeoDatabase.enabled()
                        + ",\"defaultBlocked\":" + JsonReport.stringArray(policy.blocked())
                        + ",\"defaultAllowed\":" + JsonReport.stringArray(policy.allowed()) + "}");
            }
            case "/api/analyze" -> {
                requireMethod(method, "POST");
                checkRate(ex);
                return analyze(ex);
            }
            case "/api/benchmark" -> {
                requireMethod(method, "POST");
                checkRate(ex);
                return benchmark(ex);
            }
            default -> throw new ApiException(404, "Not found");
        }
    }

    private int analyze(HttpExchange ex) throws Exception {
        Map<String, String> q = query(ex.getRequestURI());
        String source = q.getOrDefault("source", "sample");
        String strategy = q.getOrDefault("strategy", "parallel");
        int top = (int) numberParam(q, "top", 10, 1, 50);
        ResponseTimeUnit unit = parseUnit(q.getOrDefault("unit", "ms"));
        checkStrategy(strategy);
        Set<String> blocked = countries(q, "blocked", policy.blocked());
        Set<String> allowed = countries(q, "allowed", policy.allowed());
        boolean worldwide = Boolean.parseBoolean(q.getOrDefault("worldwide", "false"));

        Path temp = Files.createTempFile("log-analyzer-", ".log");
        try {
            long generateMillis = 0;
            switch (source) {
                case "sample" -> {
                    long lines = numberParam(q, "lines", 100_000, 1, limits.maxSampleLines());
                    long seed = numberParam(q, "seed", 42, 0, 1_000_000_000L);
                    acquireAnalysisSlot();
                    try {
                        long t0 = System.nanoTime();
                        LogGenerator.generate(temp, lines, seed, worldwide);
                        generateMillis = (System.nanoTime() - t0) / 1_000_000;
                        return sendJson(ex, 200, runAnalysis(temp, strategy, top, unit, source, generateMillis, blocked, allowed));
                    } finally {
                        analysisSlots.release();
                    }
                }
                case "upload" -> {
                    receiveUpload(ex, temp);
                    acquireAnalysisSlot();
                    try {
                        return sendJson(ex, 200, runAnalysis(temp, strategy, top, unit, source, 0, blocked, allowed));
                    } finally {
                        analysisSlots.release();
                    }
                }
                default -> throw new ApiException(400, "source must be sample or upload");
            }
        } finally {
            Files.deleteIfExists(temp);                      // nothing is kept after the answer is sent
        }
    }

    private String runAnalysis(Path file, String strategy, int top, ResponseTimeUnit unit, String source,
                               long generateMillis, Set<String> blocked, Set<String> allowed)
            throws IOException, InterruptedException {
        int cores = Runtime.getRuntime().availableProcessors();
        AnalysisConfig config = AnalysisConfig.builder(file)
                .strategy(strategy)
                .threads(cores)
                .chunkBytes(AnalysisConfig.suggestChunkBytes(Files.size(file), cores))
                .timeUnit(unit)
                .topN(top)
                .minRouteHits(5)
                .blockedCountries(blocked)
                .allowedCountries(allowed)
                .build();
        AnalysisResult result = Analyzer.run(config);
        String json = JsonReport.render(result);
        return json.substring(0, json.length() - 1)          // reopen the object to add two more fields
                + ",\"source\":" + JsonReport.quote(source)
                + ",\"generateMillis\":" + generateMillis + "}";
    }

    private int benchmark(HttpExchange ex) throws Exception {
        Map<String, String> q = query(ex.getRequestURI());
        long lines = numberParam(q, "lines", 100_000, 1_000, limits.maxBenchmarkLines());
        int runs = (int) numberParam(q, "runs", 3, 1, limits.maxBenchmarkRuns());
        Path temp = Files.createTempFile("log-analyzer-bench-", ".log");
        acquireAnalysisSlot();
        try {
            LogGenerator.generate(temp, lines, 42);
            int cores = Runtime.getRuntime().availableProcessors();
            Benchmark.Outcome outcome = Benchmark.run(temp, 1, runs,
                    AnalysisConfig.suggestChunkBytes(Files.size(temp), cores), cores, "ms");
            return sendJson(ex, 200, Benchmark.toJson(outcome));
        } finally {
            analysisSlots.release();
            Files.deleteIfExists(temp);
        }
    }

    /** Reads a country list parameter; when the parameter is missing the server's default is used. */
    private static Set<String> countries(Map<String, String> q, String name, Set<String> fallback) {
        String text = q.get(name);
        if (text == null) {
            return fallback;
        }
        try {
            return CountryList.parse(text);
        } catch (IllegalArgumentException e) {
            throw new ApiException(400, e.getMessage());
        }
    }

    /** Refuses a client that has used up its requests for this minute. */
    private void checkRate(HttpExchange ex) {
        if (!rateLimiter.tryAcquire(clientKey(ex))) {
            ex.getResponseHeaders().set("Retry-After", "60");
            throw new ApiException(429, "Too many requests from your connection. Please wait a minute and try again.");
        }
    }

    /**
     * Identifies the client for rate limiting. Behind a hosting platform every connection comes from the platform's
     * own (private) proxy, so only then is the X-Forwarded-For header believed, and only its LAST entry, which is the
     * one the proxy itself added. Anything a visitor puts earlier in that header is ignored. A connection from the
     * open internet cannot choose its own identity.
     */
    private static String clientKey(HttpExchange ex) {
        java.net.InetAddress peer = ex.getRemoteAddress().getAddress();
        String key = peer.getHostAddress();
        boolean proxy = peer.isLoopbackAddress() || peer.isSiteLocalAddress() || peer.isLinkLocalAddress()
                || (peer.getAddress().length == 16 && (peer.getAddress()[0] & 0xFE) == 0xFC);
        String forwarded = proxy ? ex.getRequestHeaders().getFirst("X-Forwarded-For") : null;
        if (forwarded != null) {
            String last = forwarded.substring(forwarded.lastIndexOf(',') + 1).trim();
            if (new IpParser().parse(last) != IpParser.NONE) {
                return last;
            }
        }
        return key;
    }

    private void acquireAnalysisSlot() {
        if (!analysisSlots.tryAcquire()) {
            throw new ApiException(429, "Another analysis is running. Please try again in a few seconds.");
        }
    }

    /** Streams the request body to a temp file and stops as soon as it is larger than the limit. */
    private void receiveUpload(HttpExchange ex, Path target) throws IOException {
        long max = limits.maxUploadBytes();
        String declared = ex.getRequestHeaders().getFirst("Content-Length");
        if (declared != null) {
            try {
                if (Long.parseLong(declared) > max) {
                    throw tooLarge(max);
                }
            } catch (NumberFormatException e) {
                throw new ApiException(400, "Invalid Content-Length header");
            }
        }
        if (!uploadSlots.tryAcquire()) {
            throw new ApiException(429, "Too many uploads at once. Please try again in a few seconds.");
        }
        try (InputStream in = ex.getRequestBody(); OutputStream out = Files.newOutputStream(target)) {
            byte[] buffer = new byte[64 * 1024];
            long total = 0;
            int n;
            while ((n = in.read(buffer)) != -1) {
                total += n;
                if (total > max) {
                    ex.getResponseHeaders().set("Connection", "close");
                    throw tooLarge(max);
                }
                out.write(buffer, 0, n);
            }
            if (total == 0) {
                throw new ApiException(400, "The uploaded file is empty.");
            }
        } finally {
            uploadSlots.release();
        }
    }

    private static ApiException tooLarge(long max) {
        return new ApiException(413, "File is too large. This demo accepts up to " + max / (1024 * 1024)
                + " MB. For bigger files, run the command line version.");
    }

    // ------------------------------------------------------------------ helpers

    private static void requireMethod(String actual, String expected) {
        if (!expected.equals(actual)) {
            throw new ApiException(405, "Use " + expected + " for this address");
        }
    }

    private static void checkStrategy(String name) {
        try {
            io.github.aachar0.loganalyzer.engine.ProcessingStrategy.byName(name, 1);
        } catch (IllegalArgumentException e) {
            throw new ApiException(400, e.getMessage());
        }
    }

    private static ResponseTimeUnit parseUnit(String text) {
        try {
            return ResponseTimeUnit.fromText(text);
        } catch (IllegalArgumentException e) {
            throw new ApiException(400, e.getMessage());
        }
    }

    private static long numberParam(Map<String, String> q, String name, long fallback, long min, long max) {
        String text = q.get(name);
        if (text == null) {
            return Math.min(fallback, max);
        }
        long value;
        try {
            value = Long.parseLong(text.trim());
        } catch (NumberFormatException e) {
            throw new ApiException(400, "Parameter '" + name + "' must be a whole number");
        }
        if (value < min || value > max) {
            throw new ApiException(400, "Parameter '" + name + "' must be between " + min + " and " + max);
        }
        return value;
    }

    private static Map<String, String> query(URI uri) {
        Map<String, String> result = new HashMap<>();
        String raw = uri.getRawQuery();
        if (raw == null || raw.isEmpty()) {
            return result;
        }
        String[] pairs = raw.split("&", 21);
        for (int i = 0; i < Math.min(pairs.length, 20); i++) {
            int eq = pairs[i].indexOf('=');
            String key = eq < 0 ? pairs[i] : pairs[i].substring(0, eq);
            String value = eq < 0 ? "" : pairs[i].substring(eq + 1);
            result.put(URLDecoder.decode(key, StandardCharsets.UTF_8), URLDecoder.decode(value, StandardCharsets.UTF_8));
        }
        return result;
    }

    private int sendJson(HttpExchange ex, int status, String json) throws IOException {
        return sendBytes(ex, status, "application/json; charset=utf-8", json.getBytes(StandardCharsets.UTF_8), true);
    }

    private int sendBytes(HttpExchange ex, int status, String contentType, byte[] body, boolean api) throws IOException {
        if (ex.getResponseCode() != -1) {                      // a response was already started
            return status;
        }
        ex.getResponseHeaders().set("Content-Type", contentType);
        applyHeaders(ex, api);
        ex.setAttribute("bytes", body.length);
        ex.sendResponseHeaders(status, body.length == 0 ? -1 : body.length);
        if (body.length > 0) {
            try (OutputStream out = ex.getResponseBody()) {
                out.write(body);
            }
        }
        return status;
    }

    /** Security headers on every response; the API additionally disables caching and may allow one website (CORS). */
    private void applyHeaders(HttpExchange ex, boolean api) {
        var h = ex.getResponseHeaders();
        h.set("X-Content-Type-Options", "nosniff");
        h.set("Referrer-Policy", "no-referrer");
        h.set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; "
                + "frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
        h.set("X-Frame-Options", "DENY");
        h.set("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=(), usb=()");
        h.set("Cross-Origin-Opener-Policy", "same-origin");
        h.set("Strict-Transport-Security", "max-age=15552000");      // browsers only act on this over HTTPS
        if (api) {
            h.set("Cache-Control", "no-store");
            if (!links.allowedOrigin().isEmpty()) {
                h.set("Access-Control-Allow-Origin", links.allowedOrigin());
                h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
                h.set("Access-Control-Allow-Headers", "Content-Type");
                h.set("Vary", "Origin");
            }
        } else {
            h.set("Cache-Control", "public, max-age=300");
        }
    }

    /** Writes one line per request in the same format this project analyses. The client address is replaced by "-". */
    private static void logAccess(HttpExchange ex, int status, long millis) {
        Object bytes = ex.getAttribute("bytes");
        String path = ex.getRequestURI().getRawPath().replaceAll("[^\\x21-\\x7E]", "_");
        System.out.println("- - - [" + LOG_STAMP.format(Instant.now()) + "] \"" + ex.getRequestMethod() + ' ' + path
                + " HTTP/1.1\" " + status + ' ' + (bytes == null ? "-" : bytes) + ' ' + millis);
    }

    private static String escapeHtml(String text) {
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    private static byte[] resource(String name) throws IOException {
        try (InputStream in = WebServer.class.getResourceAsStream("/static/" + name)) {
            if (in == null) {
                throw new IOException("Missing resource /static/" + name);
            }
            return in.readAllBytes();
        }
    }
}
