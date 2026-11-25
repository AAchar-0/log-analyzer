# Concurrent Log Analyzer

> A dependency-free Java 21 tool that reads very large web-server logs and reports error rates, outages, busiest minutes, slowest routes and response-time percentiles. It does the work three ways (one thread, a thread pool, and virtual threads), proves they give identical answers, and benchmarks them honestly.

**LIVE-APP:** [log-analyzer](https://log-analyzer-vjuz.onrender.com)
**Source code:** [github.com/AAchar-0/log-analyzer](https://github.com/AAchar-0/log-analyzer)
**Author:** [Anade Acharo](https://aachar-0.github.io/)

## Try the live demo

1. Open the [live app](https://log-analyzer-vjuz.onrender.com). The first load can take about a minute, because the free hosting sleeps when idle.
2. Keep **Generate a sample log**, pick a size, and click **Analyse**. Look for the four-minute outage the generator plants in every log: it appears under "Minutes with the most server errors".
3. Try **Run benchmark** to compare the three strategies on the server's CPU.
4. Or upload your own log (25 MB at most, format below). Do not upload logs with real IP addresses or other personal data.

## Contents

- [Overview](#overview)
- [Key features](#key-features)
- [How it works](#how-it-works)
- [Run it locally](#run-it-locally)
- [Command line](#command-line)
- [Benchmark](#benchmark)
- [Design decisions](#design-decisions)
- [Tech stack](#tech-stack)
- [Project structure](#project-structure)
- [Testing](#testing)
- [Deployment](#deployment)
- [Settings](#settings)
- [Limitations](#limitations)
- [Privacy and ethics](#privacy-and-ethics)
- [Technical reference](#technical-reference)
- [License](#license)

## Overview

Every server writes a log line for every request. When something breaks at 3 a.m., the answer is in those lines, but a busy service writes millions of them. This project reads such files quickly and safely, in a fixed amount of memory, and turns them into a report a person can act on.

It is part of a small connected system: the [Inventory API](https://github.com/AAchar-0/inventory-api) produces access logs in this format, and this analyzer reads them (see [docs/04](docs/04-connect-to-inventory-api.md)).

## Key features

**Built for big files**
- Streams the file in 256 KB pieces. A 478 MB log (5 million lines) was analysed with the Java heap capped at 64 MB, so memory does not grow with file size.
- Splits the file into byte ranges and gives every line to exactly one range, even when a cut lands in the middle of a line.
- Percentiles come from a fixed-size histogram instead of a sorted list of every time, so 100 million lines need the same memory as 1,000.

**Three strategies, one answer**
- `sequential`, `parallel` (fixed thread pool) and `virtual` (Java 21 virtual threads) sit behind one interface.
- Tests prove all three give byte-for-byte identical reports for many chunk sizes, including chunks smaller than one line.
- The benchmark warms up, rotates the order, reports the median, and refuses to print a speed-up if the reports differ.

**A useful report**
- Request count, 4xx and 5xx rates, bytes sent, response time average, p50, p90, p95, p99 and maximum.
- Busiest minutes, **minutes with the most server errors** (where outages show up), most requested routes, slowest routes.
- Routes are grouped: `/api/products/17` and `/api/products/18` count as `/api/products/{id}`.

**Safe to put on the internet**
- Upload size is checked while streaming, sample and benchmark sizes are capped, only one analysis runs at a time, files are deleted after use.
- Text from logs reaches the page only through `textContent`, so a hostile log cannot inject HTML. A test checks the escaping.
- Client addresses are never logged by the app itself.

## How it works

```text
log file --> split into byte ranges --> workers (one LogStats each) --> merge --> Report --> text / JSON / web page
```

1. `ChunkPlanner` cuts the file into ranges of about 1 to 8 MiB.
2. Each worker reads its range with `ChunkProcessor`, parses each line from raw bytes with `LogParser`, and counts into its own `LogStats` (no locks).
3. When a worker finishes, its `LogStats` is merged into the total.
4. `Report.from(...)` sorts and ranks the totals, and `TextReport` or `JsonReport` renders them.

## Run it locally

Needs JDK 21 (Temurin). Maven is optional.

**Without Maven (PowerShell, in the project folder):**

```powershell
.\scripts\run-without-maven.ps1 generate --lines 1000000 --out sample.log
.\scripts\run-without-maven.ps1 analyze --file sample.log --strategy all
.\scripts\run-without-maven.ps1 serve
```

Then open http://localhost:8080 for the web app.

**With Maven:**

```powershell
mvn verify
java -jar target/log-analyzer.jar serve
```

## Command line

```text
generate   --out FILE  [--lines 1000000]  [--seed 42]
analyze    --file FILE [--strategy sequential|parallel|virtual|all] [--format text|json] [--top 10]
                       [--time-unit ms|us] [--threads N] [--chunk-mb N] [--min-route-hits 10]
benchmark  --file FILE [--runs 5] [--warmups 2]
serve      [--port 8080] [--host 0.0.0.0]
```

Log line format (common web-server format plus the response time at the end):

```text
192.0.2.7 - - [01/Nov/2026:10:15:32 +0000] "GET /api/products/42 HTTP/1.1" 200 1532 18
```

## Benchmark

Parallel code only speeds up work that the CPU limits, and virtual threads help work that waits. Parsing a log is mostly CPU work, so the results depend heavily on how many cores the machine has. Measured by `benchmark` on my laptop:

| Machine | Lines | Strategy | Median (ms) | Speed-up |
|---|---|---|---|---|
| PASTE-YOUR-CPU-HERE, PASTE-CORES-HERE cores | 5,000,000 | sequential | PASTE | 1.00x |
| | | parallel | PASTE | PASTE |
| | | virtual | PASTE | PASTE |

To reproduce:

```powershell
.\scripts\run-without-maven.ps1 generate --lines 5000000 --out sample.log
.\scripts\run-without-maven.ps1 benchmark --file sample.log --runs 5 --warmups 2
```

On a single-core cloud container the three strategies take about the same time, and I publish that too: a correct measurement is more useful than a flattering one.

## Design decisions

| Decision | Why |
|---|---|
| Per-worker counters, merged at the end | Shared counters need locks, and lock traffic can make parallel code slower than sequential code. |
| Histogram for percentiles | Constant memory, exact to 1 ms up to 10 s, and merges by addition. |
| Parse from bytes, not Strings | Avoids allocating millions of temporary objects. |
| "A line belongs to the range containing its first byte" | The one rule that makes cut-anywhere parallel reading correct. |
| Semaphore around virtual threads | A 10 GB file has over a thousand chunks; unlimited concurrent buffers would run out of memory. |
| Synthetic logs | Real logs contain IP addresses, which are personal data under many privacy laws. |
| JDK built-in HTTP server | The whole project has zero runtime dependencies: nothing to update, nothing to be hacked through. |
| Seeded generator | The same seed gives the same file, so tests and benchmarks are repeatable. |

## Tech stack

Java 21 (records, sealed interfaces, pattern matching, virtual threads), JDK `HttpServer`, JUnit 5, Maven, Docker, GitHub Actions, Render.

## Project structure

```text
src/main/java/io/github/aachar0/loganalyzer/
  Main.java            command line
  model/               LogEntry, Malformed, ParseResult (sealed)
  parse/               LogParser, ResponseTimeUnit
  stats/               LogStats, LatencyHistogram, RouteStats
  engine/              strategies, ChunkProcessor, Analyzer, Benchmark, AnalysisConfig (builder)
  report/              Report, TextReport, JsonReport
  gen/                 LogGenerator (synthetic logs)
  web/                 WebServer
  tour/                ConcurrencyTour: runnable Java refresher
src/main/resources/static/   index.html, app.js, style.css
src/test/java/...            35 tests
docs/                        reference sheets and guides
```

## Testing

```powershell
mvn verify
```

The tests check the parser against good and bad lines, the histogram's percentiles, that every strategy agrees for many chunk sizes (including edge cases: no trailing newline, Windows line endings, empty files, a line longer than the buffer), that the generator is reproducible, JSON escaping, and the web endpoints including oversized uploads.

## Deployment

Runs on Render as a Docker web service, built from the `Dockerfile` in this repository (free instance, health check path `/health`, no environment variables needed). Every push to `main` redeploys it, and GitHub Actions builds and tests the code first.

## Settings

Environment variables (all optional):

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | 8080 | Port to listen on (Render sets it) |
| `MAX_UPLOAD_MB` | 25 | Largest upload |
| `MAX_SAMPLE_LINES` | 1000000 | Largest generated sample |
| `MAX_BENCHMARK_LINES` | 300000 | Largest benchmark log |
| `MAX_BENCHMARK_RUNS` | 5 | Most measured runs |
| `MAX_CONCURRENT` | 1 | Analyses running at once |
| `PORTFOLIO_URL` | portfolio site | Footer link |
| `SOURCE_URL` | this repository | Footer link |
| `ALLOWED_ORIGIN` | none | A website allowed to call the API from a browser (CORS) |

## Limitations

- The hosted demo is capped on purpose (free hosting has little memory and CPU). The command line has no such limit.
- Memory grows with the number of distinct minutes and distinct routes. A log with millions of unique URLs would use a lot of memory; the demo's upload cap prevents that.
- Percentiles are exact up to 10 seconds; slower requests are grouped, and the true maximum is still reported.
- Times are grouped by minute in UTC.
- One log format is supported. Other formats need a new parser.
- The demo has no login; it is protected by size and concurrency limits only.

## Privacy and ethics

Sample logs are generated, use only address ranges reserved for documentation (RFC 5737), and describe no real person. The web app stores nothing: uploads live in a temporary file for the length of one request. The app never writes client addresses to its own log. Before analysing real logs, check that you may process the addresses and user names they contain.

## Technical reference

See the [docs](docs/) folder: project map, a concurrency reference sheet, command and format reference, and how to connect to the Inventory API.

## License

[MIT](LICENSE). Copyright (c) 2026 Anade Acharo.
