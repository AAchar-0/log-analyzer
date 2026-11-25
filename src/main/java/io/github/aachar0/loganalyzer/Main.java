package io.github.aachar0.loganalyzer;

import io.github.aachar0.loganalyzer.engine.AnalysisConfig;
import io.github.aachar0.loganalyzer.engine.AnalysisResult;
import io.github.aachar0.loganalyzer.engine.Analyzer;
import io.github.aachar0.loganalyzer.engine.Benchmark;
import io.github.aachar0.loganalyzer.engine.ProcessingStrategy;
import io.github.aachar0.loganalyzer.gen.LogGenerator;
import io.github.aachar0.loganalyzer.parse.ResponseTimeUnit;
import io.github.aachar0.loganalyzer.report.JsonReport;
import io.github.aachar0.loganalyzer.report.TextReport;
import io.github.aachar0.loganalyzer.web.WebServer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Command line entry point.
 *
 *   java -jar log-analyzer.jar generate  --lines 1000000 --out sample.log [--seed 42]
 *   java -jar log-analyzer.jar analyze   --file sample.log [--strategy sequential|parallel|virtual|all]
 *                                        [--format text|json] [--top 10] [--time-unit ms|us]
 *   java -jar log-analyzer.jar benchmark --file sample.log [--runs 5] [--warmups 2]
 *   java -jar log-analyzer.jar serve     [--port 8080]
 */
public final class Main {

    private static final Set<String> VALUE_OPTIONS = Set.of("lines", "out", "seed", "file", "strategy", "format",
            "top", "time-unit", "runs", "warmups", "threads", "chunk-mb", "min-route-hits", "port", "host");

    private Main() {
    }

    public static void main(String[] args) {
        int exit;
        try {
            exit = run(args);
        } catch (IllegalArgumentException e) {
            System.err.println("Error: " + e.getMessage());
            System.err.println("Run with 'help' to see the commands.");
            exit = 2;
        } catch (IOException e) {
            System.err.println("File problem: " + e.getMessage());
            exit = 1;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            exit = 1;
        }
        if (exit != 0) {
            System.exit(exit);
        }
    }

    static int run(String[] args) throws IOException, InterruptedException {
        if (args.length == 0) {
            printHelp();
            return 0;
        }
        String command = args[0];
        Map<String, String> options = parseOptions(args);
        switch (command) {
            case "generate" -> {
                Path out = Path.of(required(options, "out"));
                long lines = Long.parseLong(options.getOrDefault("lines", "1000000"));
                long seed = Long.parseLong(options.getOrDefault("seed", "42"));
                long size = LogGenerator.generate(out, lines, seed);
                System.out.printf("Wrote %,d lines (%.1f MB) to %s%n", lines, size / 1_000_000.0, out);
                return 0;
            }
            case "analyze" -> {
                return analyze(options);
            }
            case "benchmark" -> {
                Path file = existingFile(options);
                Benchmark.Outcome outcome = Benchmark.run(file,
                        Integer.parseInt(options.getOrDefault("warmups", "2")),
                        Integer.parseInt(options.getOrDefault("runs", "5")),
                        chunkBytes(options), threads(options), options.getOrDefault("time-unit", "ms"));
                System.out.print(Benchmark.toText(outcome));
                return outcome.identical() ? 0 : 3;
            }
            case "serve" -> {
                int port = Integer.parseInt(options.getOrDefault("port", envOr("PORT", "8080")));
                WebServer server = WebServer.create(options.getOrDefault("host", "0.0.0.0"), port,
                        WebServer.Limits.fromEnvironment(), WebServer.Links.fromEnvironment());
                server.start();
                System.out.println("Log analyzer listening on port " + server.port());
                Thread.currentThread().join();                    // keep the program alive; Ctrl+C stops it
                return 0;
            }
            case "help", "--help", "-h" -> {
                printHelp();
                return 0;
            }
            default -> throw new IllegalArgumentException("Unknown command: " + command);
        }
    }

    private static int analyze(Map<String, String> options) throws IOException, InterruptedException {
        Path file = existingFile(options);
        String strategy = options.getOrDefault("strategy", "parallel");
        String format = options.getOrDefault("format", "text");
        if (!format.equals("text") && !format.equals("json")) {
            throw new IllegalArgumentException("--format must be text or json");
        }
        List<String> names = strategy.equals("all")
                ? ProcessingStrategy.all(1).stream().map(ProcessingStrategy::name).toList()
                : List.of(strategy);

        AnalysisResult first = null;
        boolean allAgree = true;
        for (String name : names) {
            AnalysisConfig config = AnalysisConfig.builder(file)
                    .strategy(name)
                    .threads(threads(options))
                    .chunkBytes(chunkBytes(options))
                    .timeUnit(ResponseTimeUnit.fromText(options.getOrDefault("time-unit", "ms")))
                    .topN(Integer.parseInt(options.getOrDefault("top", "10")))
                    .minRouteHits(Integer.parseInt(options.getOrDefault("min-route-hits", "10")))
                    .build();
            AnalysisResult result = Analyzer.run(config);
            if (first == null) {
                first = result;
            } else if (!first.report().equals(result.report())) {
                allAgree = false;
            }
            if (names.size() == 1) {
                System.out.println(format.equals("json") ? JsonReport.render(result) : TextReport.render(result));
            } else {
                System.out.printf("%-10s %,10d requests in %8.1f ms%n", name, result.report().requests(), result.millis());
            }
        }
        if (names.size() > 1) {
            System.out.println(allAgree ? "All strategies agree: yes" : "All strategies agree: NO (this is a bug)");
            if (allAgree) {
                System.out.println();
                System.out.println(format.equals("json") ? JsonReport.render(first) : TextReport.render(first));
            }
        }
        return allAgree ? 0 : 3;
    }

    private static Map<String, String> parseOptions(String[] args) {
        Map<String, String> options = new HashMap<>();
        for (int i = 1; i < args.length; i++) {
            String arg = args[i];
            if (!arg.startsWith("--")) {
                throw new IllegalArgumentException("Unexpected argument: " + arg);
            }
            String key = arg.substring(2);
            if (!VALUE_OPTIONS.contains(key)) {
                throw new IllegalArgumentException("Unknown option: " + arg);
            }
            if (i + 1 >= args.length) {
                throw new IllegalArgumentException("Option " + arg + " needs a value");
            }
            options.put(key, args[++i]);
        }
        return options;
    }

    private static String required(Map<String, String> options, String key) {
        String value = options.get(key);
        if (value == null) {
            throw new IllegalArgumentException("Missing required option --" + key);
        }
        return value;
    }

    private static Path existingFile(Map<String, String> options) {
        Path file = Path.of(required(options, "file"));
        if (!Files.isRegularFile(file)) {
            throw new IllegalArgumentException("File not found: " + file);
        }
        return file;
    }

    private static int threads(Map<String, String> options) {
        return Integer.parseInt(options.getOrDefault("threads",
                Integer.toString(Runtime.getRuntime().availableProcessors())));
    }

    private static long chunkBytes(Map<String, String> options) {
        String mb = options.get("chunk-mb");
        return mb == null ? AnalysisConfig.DEFAULT_CHUNK_BYTES : (long) (Double.parseDouble(mb) * 1024 * 1024);
    }

    private static String envOr(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value;
    }

    private static void printHelp() {
        System.out.println("""
                Concurrent Log Analyzer

                Commands:
                  generate   Write a synthetic web-server log.
                             --out FILE (required)  --lines N (default 1000000)  --seed N (default 42)
                  analyze    Read a log and print the report.
                             --file FILE (required)  --strategy sequential|parallel|virtual|all (default parallel)
                             --format text|json  --top N  --time-unit ms|us  --threads N  --chunk-mb N
                  benchmark  Time all three strategies fairly and check they agree.
                             --file FILE (required)  --runs N (default 5)  --warmups N (default 2)
                  serve      Start the web app (uses the PORT environment variable, default 8080).
                             --port N  --host ADDRESS
                  help       Show this text.

                Log line format:
                  192.0.2.7 - - [01/Nov/2026:10:15:32 +0000] "GET /api/products/42 HTTP/1.1" 200 1532 18
                  (client, identity, user, [time], "request", status, bytes, response time in ms)
                """);
    }
}
