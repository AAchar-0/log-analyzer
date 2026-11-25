# Reference Sheet 03: Commands and Log Format

## Commands (PowerShell, from the project folder)

```powershell
.\scripts\run-without-maven.ps1 generate --lines 1000000 --out sample.log --seed 42
.\scripts\run-without-maven.ps1 analyze --file sample.log
.\scripts\run-without-maven.ps1 analyze --file sample.log --strategy all
.\scripts\run-without-maven.ps1 analyze --file sample.log --format json --top 5
.\scripts\run-without-maven.ps1 benchmark --file sample.log --runs 5 --warmups 2
.\scripts\run-without-maven.ps1 serve --port 8080
```

After `mvn package`, replace the script with `java -jar target/log-analyzer.jar`.

Exit codes: 0 fine, 1 file problem, 2 wrong arguments, 3 strategies disagreed (a bug).

## Log line

```text
192.0.2.7 - - [01/Nov/2026:10:15:32 +0000] "GET /api/products/42?size=20 HTTP/1.1" 200 1532 18
```

| Field | Notes |
|---|---|
| 192.0.2.7 | Client address. Read past, never stored. |
| `-` `-` | Identity and user name. Read past. |
| `[01/Nov/2026:10:15:32 +0000]` | Fixed-width time with offset; converted to UTC minutes. |
| `"GET /path HTTP/1.1"` | Method must be capital letters; path must start with `/`. |
| 200 | Status 100 to 599. |
| 1532 | Response bytes, or `-` for none. |
| 18 | Time in ms (use `--time-unit us` if your server logs microseconds). |

Anything that does not match is counted as **malformed** and skipped.

## Reading the report

- **p95 = 113 ms** means 95% of requests took 113 ms or less. Averages hide slow outliers; percentiles show them.
- **Minutes with the most server errors** is where an outage shows: a sudden block of 5xx.
- **4xx** are client mistakes (bad login, missing item); **5xx** are the server failing. Page someone for 5xx.
