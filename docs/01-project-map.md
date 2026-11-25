# Reference Sheet 01: Project Map

Read the files in this order and you will understand the whole program.

| Order | File | What it does |
|---|---|---|
| 1 | `model/LogEntry.java`, `Malformed.java`, `ParseResult.java` | The data: one good line, or one bad line. `ParseResult` is **sealed**: only those two exist. |
| 2 | `parse/LogParser.java` | Turns the bytes of one line into a `ParseResult`. Never throws on bad input. |
| 3 | `stats/LatencyHistogram.java` | Counts response times in 1 ms buckets; answers percentiles. |
| 4 | `stats/LogStats.java` | All counters for one worker. `merge()` adds two of them. |
| 5 | `engine/ChunkPlanner.java`, `Range.java` | Cuts a file into byte ranges. |
| 6 | `engine/ChunkProcessor.java` | Reads one range. Owns the rule "a line belongs to the range holding its first byte". |
| 7 | `engine/ProcessingStrategy.java` + 3 implementations | The three ways to run the work. |
| 8 | `engine/AnalysisConfig.java` | Builder for the settings. |
| 9 | `engine/Analyzer.java`, `Benchmark.java` | Run once / run fairly many times. |
| 10 | `report/*` | Sort and rank the totals; draw them as text or JSON. |
| 11 | `gen/LogGenerator.java` | Makes realistic synthetic logs, with one planted outage. |
| 12 | `web/WebServer.java` + `static/*` | The web app. |
| 13 | `Main.java` | The command line. |
| 14 | `tour/ConcurrencyTour.java` | Run it: a guided Java refresher, 14 lessons. |

## Patterns used

- **Strategy**: `ProcessingStrategy` and its three classes.
- **Builder**: `AnalysisConfig.builder(...)...build()`.
- **Pipeline**: split, count, merge, rank, render.
- **Map-reduce in miniature**: workers "map" ranges to `LogStats`; `merge` "reduces" them.

## Where each Java idea appears

| Idea | Where |
|---|---|
| Records | `LogEntry`, `Range`, `Report`, `AnalysisResult` |
| Sealed interface + pattern-matching switch | `ParseResult` and `LogStats.accept` |
| Enum with data | `ResponseTimeUnit` |
| try-with-resources | strategies (channel, executor) |
| Virtual threads | `VirtualThreadStrategy`, `WebServer` |
| Thread pool and completion service | `ParallelStrategy` |
| Semaphore | `VirtualThreadStrategy`, `WebServer` |
| Text blocks | `Main.printHelp` |
