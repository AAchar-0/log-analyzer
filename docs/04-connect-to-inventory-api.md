# Guide 04: Connecting the Inventory API to the Log Analyzer

The analyzer reads the common web-server log format with the response time at the end. Spring Boot's embedded Tomcat can write exactly that. Add these lines to `src/main/resources/application.yml` of the inventory API **under the existing `server:` block** (keep `port` and `forward-headers-strategy`):

```yaml
server:
  tomcat:
    accesslog:
      enabled: true
      directory: logs
      prefix: access
      suffix: .log
      pattern: '%h %l %u %t "%r" %s %b %D'
```

`%h` client, `%l` identity, `%u` user, `%t` time, `%r` request line, `%s` status, `%b` bytes, `%D` processing time.

## Check the time unit with ONE request

Tomcat's `%D` is documented as milliseconds in some versions and microseconds in others. Do not guess:

1. Run the API locally, call one endpoint, open `logs/access.<date>.log`.
2. A fast request should show a small number. If a request that obviously took a few milliseconds shows a number in the thousands, it is microseconds.
3. Analyse with `--time-unit us` in that case (the web page has the same choice for uploads).

## Notes

- Add `logs/` to the API's `.gitignore`.
- Access logs contain client IP addresses, which are personal data under many privacy laws. Keep them private, delete them on a schedule, and do not upload them to the public demo.
- On Render's free tier the disk is erased on every restart, so collect logs somewhere permanent before relying on them. A later step is an endpoint or job that ships them to the analyzer.
- `%u` may be `-` for JWT calls; that is fine, the analyzer ignores it.
