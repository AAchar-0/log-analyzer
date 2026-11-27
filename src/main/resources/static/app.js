"use strict";
/*
 * Page logic. SAFETY RULE: every piece of text that comes from the server (route names come from log files,
 * which anyone can upload) is put on the page with textContent, never innerHTML. That makes it impossible for
 * a log line to inject HTML or scripts into the page.
 */
(() => {
  const $ = (id) => document.getElementById(id);
  const fmt = (n) => Number(n).toLocaleString("en-US");
  const dec = (n, d = 1) => Number(n).toLocaleString("en-US", { minimumFractionDigits: d, maximumFractionDigits: d });

  /** Creates an element: el("td", {class: "num"}, "text", childElement). Text children are inserted as text. */
  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (value !== null && value !== undefined) node.setAttribute(key, value);
    }
    for (const child of children) {
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  function table(headers, rows) {
    const head = el("tr", {}, ...headers.map((h) => el("th", { class: h.num ? "num" : null }, h.text)));
    const body = rows.map((cells) => el("tr", {}, ...cells));
    return el("div", { class: "table-wrap" }, el("table", {}, el("thead", {}, head), el("tbody", {}, ...body)));
  }

  const cell = (text, cls) => el("td", { class: cls || null }, text);
  const barCell = (value, max, bad) => {
    const bar = el("span", { class: "bar" + (bad ? " bad" : "") });
    bar.style.width = (max > 0 ? Math.max(1, (100 * value) / max) : 0) + "%";
    return el("td", { class: "barcell" }, bar);
  };

  async function post(url, body) {
    const response = await fetch(url, { method: "POST", body });
    let data;
    try { data = await response.json(); } catch { data = { error: "The server sent an unexpected answer." }; }
    if (!response.ok) throw new Error(data.error || "Request failed (" + response.status + ")");
    return data;
  }

  function setStatus(id, text, isError) {
    const node = $(id);
    node.textContent = text;
    node.classList.toggle("error", Boolean(isError));
  }

  function fillSelect(select, values, max, selected) {
    select.replaceChildren();
    for (const value of values.filter((v) => v <= max)) {
      const option = el("option", { value }, fmt(value));
      if (value === selected) option.selected = true;
      select.append(option);
    }
  }

  // ---------------------------------------------------------------- report rendering
  function renderReport(data) {
    const r = data.report;
    const box = $("report");
    box.replaceChildren();

    if (r.requests === 0) {
      box.append(el("p", { class: "verdict bad" }, "No valid log lines were found (" + fmt(r.malformedLines) +
        " malformed). Check that the file uses the format shown below."));
      box.hidden = false;
      return;
    }

    const card = (label, value) => el("div", { class: "card" }, el("div", { class: "label" }, label), el("div", { class: "value" }, value));
    box.append(el("div", { class: "cards" },
      card("Requests", fmt(r.requests)),
      card("Server errors (5xx)", dec(r.serverErrorPercent, 2) + "%"),
      card("Client errors (4xx)", dec(r.clientErrorPercent, 2) + "%"),
      card("Median response", r.latency.p50 + " ms"),
      card("95th percentile", r.latency.p95 + " ms"),
      card("Counted in", dec(data.millis, 0) + " ms (" + data.strategy + ")")));

    box.append(el("p", {}, "Period: " + r.firstMinute + " to " + r.lastMinute + ". Malformed lines skipped: " + fmt(r.malformedLines) +
      ". Average response " + dec(r.latency.averageMs) + " ms, 99th percentile " + r.latency.p99 + " ms, slowest " + fmt(r.latency.maxMs) + " ms."));

    const maxStatus = Math.max(...r.statuses.map((s) => s.count));
    box.append(el("h3", {}, "Status codes"), table(
      [{ text: "Code" }, { text: "Requests", num: true }, { text: "" }],
      r.statuses.map((s) => [cell(s.status), cell(fmt(s.count), "num"), barCell(s.count, maxStatus, s.status >= 500)])));

    box.append(el("h3", {}, "Minutes with the most server errors (outages show up here)"));
    if (r.worstErrorMinutes.length === 0) {
      box.append(el("p", {}, "No server errors in this log."));
    } else {
      const maxErr = Math.max(...r.worstErrorMinutes.map((m) => m.serverErrors));
      box.append(table(
        [{ text: "Minute" }, { text: "5xx", num: true }, { text: "Requests", num: true }, { text: "" }],
        r.worstErrorMinutes.map((m) => [cell(m.minute), cell(fmt(m.serverErrors), "num"), cell(fmt(m.requests), "num"), barCell(m.serverErrors, maxErr, true)])));
    }

    const maxMinute = Math.max(...r.busiestMinutes.map((m) => m.requests));
    box.append(el("h3", {}, "Busiest minutes"), table(
      [{ text: "Minute" }, { text: "Requests", num: true }, { text: "" }],
      r.busiestMinutes.map((m) => [cell(m.minute), cell(fmt(m.requests), "num"), barCell(m.requests, maxMinute, false)])));

    const maxHits = Math.max(...r.topRoutes.map((x) => x.hits));
    box.append(el("h3", {}, "Most requested routes"), table(
      [{ text: "Route" }, { text: "Requests", num: true }, { text: "Avg ms", num: true }, { text: "" }],
      r.topRoutes.map((x) => [cell(x.route, "route"), cell(fmt(x.hits), "num"), cell(dec(x.averageMs), "num"), barCell(x.hits, maxHits, false)])));

    box.append(el("h3", {}, "Slowest routes (by average, at least 5 requests)"), table(
      [{ text: "Route" }, { text: "Avg ms", num: true }, { text: "Max ms", num: true }, { text: "Requests", num: true }],
      r.slowestRoutes.map((x) => [cell(x.route, "route"), cell(dec(x.averageMs), "num"), cell(fmt(x.maxMs), "num"), cell(fmt(x.hits), "num")])));

    renderGeo(box, r.geo);

    box.hidden = false;
  }

  // Login attempts by country. Names of countries and cities are text from a data file, shown with textContent like
  // everything else on this page.
  // "Nairobi (2,633), Mombasa (870)". When two places share a city name, the region is added to tell them apart.
  function cityText(cities) {
    if (cities.length === 0) return "-";
    const names = cities.map((x) => x.city || x.region || "city unknown");
    return cities.map((x, i) => {
      const twin = names.some((n, j) => j !== i && n === names[i]);
      return names[i] + (twin && x.region && x.city ? " - " + x.region : "") + " (" + fmt(x.attempts) + ")";
    }).join(", ");
  }

  function countryTable(list, maxAttempts) {
    return table(
      [{ text: "Country" }, { text: "Attempts", num: true }, { text: "Succeeded", num: true }, { text: "Failed", num: true },
        { text: "Nearest cities (attempts)" }, { text: "" }],
      list.map((c) => [
        el("td", {}, c.code + " " + c.name, c.restricted ? el("div", { class: "flag" }, "MALICIOUS AREA") : ""),
        cell(fmt(c.attempts), "num"), cell(fmt(c.successes), "num"), cell(fmt(c.failures), "num"),
        el("td", { class: "cities" }, cityText(c.nearestCities)),
        barCell(c.attempts, maxAttempts, c.restricted)]));
  }

  function renderGeo(box, g) {
    box.append(el("h3", {}, "Login attempts by country"));
    if (!g) return;
    if (g.loginAttempts === 0) {
      box.append(el("p", {}, "No login attempts in this log (POST requests to a route ending in /login or /signin)."));
      return;
    }
    if (!g.available) {
      box.append(el("p", { class: "verdict bad" }, "Location data is not available on this server, so countries cannot be shown."));
      return;
    }
    const card = (label, value, bad) => el("div", { class: "card" + (bad ? " bad" : "") }, el("div", { class: "label" }, label), el("div", { class: "value" }, value));
    const cards = [card("Login attempts", fmt(g.loginAttempts)), card("Countries seen", fmt(g.countriesSeen))];
    if (g.policy.configured) {
      cards.push(card("From restricted areas", fmt(g.restricted.attempts) + " (" + dec(g.restricted.percentOfLocated, 1) + "%)", g.restricted.attempts > 0));
      cards.push(card("Restricted logins that SUCCEEDED", fmt(g.restricted.successes), g.restricted.successes > 0));
    }
    box.append(el("div", { class: "cards" }, ...cards));

    if (g.policy.configured) {
      box.append(el("p", {}, "Areas you do not deal in: " + (g.policy.blocked.join(", ") || "none listed") +
        (g.policy.allowed.length ? ". Only allowed: " + g.policy.allowed.join(", ") : "") +
        ". Logins from any other area than allowed are treated as malicious."));
      if (g.restricted.successes > 0) {
        box.append(el("p", { class: "verdict bad" }, fmt(g.restricted.successes) +
          " login(s) from restricted areas were accepted. Treat those accounts as possibly compromised."));
      }
    } else {
      box.append(el("p", {}, "No areas set. Type the country codes of areas you do not deal in (for example RU, CN) above and analyse again to flag logins from there as malicious."));
    }
    if (g.unknownAttempts > 0) {
      box.append(el("p", { class: "cities" }, fmt(g.unknownAttempts) + " attempt(s) could not be placed (private, reserved or unlisted address, or no address in the log)."));
    }

    const top = Math.max(...g.topCountries.map((c) => c.attempts), 1);
    box.append(el("h3", {}, "Top countries trying to log in"), countryTable(g.topCountries, top));
    box.append(el("h3", {}, "Bottom countries (fewest attempts, among countries that tried)"), countryTable(g.bottomCountries, top));
    if (g.restrictedCountries.length > 0) {
      box.append(el("h3", {}, "Restricted areas trying to log in (treated as malicious)"), countryTable(g.restrictedCountries, top));
    }
    box.append(el("p", { class: "cities" }, "Locations are estimates made from IP addresses. People using a VPN or a mobile network appear where their provider's server is. " + g.source));
  }

  function renderBenchmark(data) {
    const box = $("bench-result");
    box.replaceChildren();
    const maxTime = Math.max(...data.timings.map((t) => t.medianMs));
    box.append(
      el("p", {}, fmt(data.requests) + " requests, " + dec(data.fileBytes / 1e6) + " MB, " + data.cores + " CPU core(s) on this server, " +
        data.warmups + " warm-up and " + data.runs + " measured runs per strategy."),
      table(
        [{ text: "Strategy" }, { text: "Median ms", num: true }, { text: "Fastest ms", num: true }, { text: "Speed-up vs sequential", num: true }, { text: "" }],
        data.timings.map((t) => [cell(t.strategy), cell(dec(t.medianMs), "num"), cell(dec(t.minMs), "num"), cell(dec(t.speedup, 2) + "x", "num"), barCell(t.medianMs, maxTime, false)])),
      el("p", { class: "verdict" + (data.identical ? "" : " bad") },
        data.identical ? "All three strategies produced identical reports." : "The strategies produced different reports. Do not trust these numbers."),
      el("p", {}, data.cores <= 1
        ? "This server has a single CPU core, so parallel code cannot be much faster here. Run the command line version on a multi-core computer to see the real speed-up."
        : "Parallel code speeds up CPU-bound work such as parsing. Virtual threads mainly help work that waits, so a similar time to the thread pool is expected."));
    box.hidden = false;
  }

  // ---------------------------------------------------------------- wiring
  async function init() {
    let config = { maxUploadMb: 25, maxSampleLines: 100000, maxBenchmarkLines: 100000, maxBenchmarkRuns: 3 };
    try { config = await (await fetch("/api/config")).json(); } catch { /* keep defaults */ }

    fillSelect($("lines"), [10000, 50000, 100000, 250000, 500000, 1000000, 2000000, 5000000], config.maxSampleLines, 100000);
    fillSelect($("bench-lines"), [10000, 50000, 100000, 200000, 300000, 500000, 1000000], config.maxBenchmarkLines, 100000);
    fillSelect($("bench-runs"), [1, 3, 5, 7, 9], config.maxBenchmarkRuns, 3);
    $("max-upload").textContent = config.maxUploadMb;
    $("blocked").value = (config.defaultBlocked || []).join(", ");
    $("allowed").value = (config.defaultAllowed || []).join(", ");

    for (const radio of document.querySelectorAll('input[name="source"]')) {
      radio.addEventListener("change", () => {
        const upload = document.querySelector('input[name="source"]:checked').value === "upload";
        $("sample-options").hidden = upload;
        $("upload-options").hidden = !upload;
      });
    }

    $("analyse-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const source = document.querySelector('input[name="source"]:checked').value;
      const params = new URLSearchParams({ source, strategy: $("strategy").value });
      let body = null;
      params.set("blocked", $("blocked").value.trim());
      params.set("allowed", $("allowed").value.trim());
      if (source === "sample") {
        params.set("lines", $("lines").value);
        params.set("seed", $("seed").value || "42");
        if ($("worldwide").checked) params.set("worldwide", "true");
      } else {
        const file = $("file").files[0];
        if (!file) { setStatus("analyse-status", "Choose a log file first.", true); return; }
        if (file.size > config.maxUploadMb * 1024 * 1024) {
          setStatus("analyse-status", "That file is larger than " + config.maxUploadMb + " MB. Use the command line version for big files.", true);
          return;
        }
        params.set("unit", $("unit").value);
        body = file;
      }
      $("analyse-button").disabled = true;
      $("report").hidden = true;
      setStatus("analyse-status", "Working... the first request can take up to a minute while the free server wakes up.");
      try {
        const data = await post("/api/analyze?" + params, body);
        setStatus("analyse-status", "Done. " + fmt(data.report.requests) + " requests analysed" +
          (data.generateMillis ? " (generating the sample took " + fmt(data.generateMillis) + " ms)." : "."));
        renderReport(data);
      } catch (error) {
        setStatus("analyse-status", error.message, true);
      } finally {
        $("analyse-button").disabled = false;
      }
    });

    $("bench-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      $("bench-button").disabled = true;
      $("bench-result").hidden = true;
      setStatus("bench-status", "Benchmarking... this runs every strategy several times, so it can take a while.");
      try {
        const params = new URLSearchParams({ lines: $("bench-lines").value, runs: $("bench-runs").value });
        const data = await post("/api/benchmark?" + params, null);
        setStatus("bench-status", "Done.");
        renderBenchmark(data);
      } catch (error) {
        setStatus("bench-status", error.message, true);
      } finally {
        $("bench-button").disabled = false;
      }
    });
  }

  init();
})();
