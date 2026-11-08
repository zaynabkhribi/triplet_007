/* AEGIS LOOP — Guardian live timeline client.
 * Tails the append-only audit via GET /v1/verdict?since=<seq> and renders each
 * event into a swim-lane. Dependency-light (no framework) so it can't break live.
 * Poll interval mirrors config.yaml timeline.poll_interval_ms (default 500ms).
 *
 * Lane contract (spec R2: reading -> verdict -> decision -> action -> witness):
 *   twin     reading.accepted / reading.rejected / action.*   (what the city says & does)
 *   guardian passport.issued / witness.*                      (what may be believed)
 *   brain    decision.proposed / decision.refused             (what we choose to do)
 *   witness  witness.recorded                                 (did it actually happen)
 */
(function () {
  "use strict";
  var POLL_MS = 700;
  var lastSeq = 0;
  var firstTs = null;
  var counts = { total: 0, accepted: 0, rejected: 0, refused: 0 };

  var params = new URLSearchParams(location.search);
  var mode = params.get("mode") || "LOCAL-MOCK";
  var modeEl = document.getElementById("mode");
  modeEl.textContent = mode;
  modeEl.className = "badge " + (mode === "LIVE-TRIPLET" ? "live" : "mock");

  function esc(v) {
    return String(v === undefined || v === null ? "" : v)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  function laneFor(ev) {
    var e = ev.event || "";
    if (e.indexOf("witness") === 0) return "witness";
    if (e.indexOf("passport") === 0 || e.indexOf("verdict") === 0) return "guardian";
    if (e.indexOf("decision") === 0) return "brain";
    if (e.indexOf("reading.rejected") === 0) return "guardian";
    if (e.indexOf("reading") === 0) return "twin";
    if (e.indexOf("action") === 0) return "twin";
    return "guardian";
  }

  function clsFor(ev) {
    var e = ev.event || "";
    var code = ev.code || "";
    var disp = ev.disposition || "";
    if (ev.result === "MISMATCH" || e === "witness.mismatch") return "bad";
    if (e === "decision.refused") return "warn";
    if (disp === "MALICIOUS" || disp === "RESTRICT") return "bad";
    if (disp === "SUSPECT") return "warn";
    if (e === "witness.recorded" || e === "witness.confirmed") return "ok";
    if (e === "passport.issued") return disp === "TRUSTED" ? "ok" : "warn";
    if (e === "decision.proposed") return "ok";
    if (e === "action.requested") return "info";
    if (e === "reading.rejected") return "warn";
    if (e === "reading.accepted") return "ok";
    if (code === "TAMPER" || code === "SPOOF" || code === "REPLAY") return "bad";
    if (code === "DUPLICATE" || code === "STALE" || code === "UNKNOWN_DEVICE") return "warn";
    return "info";
  }

  function relMs(ts) {
    if (!firstTs) firstTs = ts;
    var d = new Date(ts) - new Date(firstTs);
    return (d >= 0 ? "+" : "") + d + "ms";
  }

  /* One readable line per event kind. The jury must be able to follow a single
   * cause-and-effect chain: reading -> verdict -> decision -> action -> witness. */
  function detailFor(ev) {
    var e = ev.event || "";
    var bits = [];

    if (e.indexOf("reading") === 0) {
      if (ev.sensor_id) bits.push(ev.sensor_id);
      if (ev.observed_property) {
        var v = ev.observed_property;
        if (ev.value !== undefined && ev.value !== null) v += "=" + ev.value;
        bits.push(v);
      }
      if (ev.zone) bits.push("[" + ev.zone + "]");
      if (ev.disposition) {
        bits.push(ev.disposition + (ev.trust !== undefined ? " " + ev.trust : ""));
      }
      if (ev.reason_codes && ev.reason_codes.length) bits.push("(" + ev.reason_codes.join(",") + ")");
      if (ev.code && ev.code !== "ACCEPTED") bits.push(ev.code);
      return bits.join("  ");
    }

    if (e === "passport.issued") {
      bits.push(ev.passport_id || "passport");
      if (ev.zone) bits.push("[" + ev.zone + "]");
      if (ev.disposition) bits.push(ev.disposition + (ev.trust !== undefined ? " " + ev.trust : ""));
      var allowed = ev.allowed_actions || [];
      if (allowed.length) bits.push("allows " + allowed.join("/"));
      else bits.push("allows NOTHING");
      if (ev.reason_codes && ev.reason_codes.length) bits.push("(" + ev.reason_codes.join(",") + ")");
      return bits.join("  ");
    }

    if (e.indexOf("decision") === 0) {
      if (ev.action) bits.push(ev.action);
      if (ev.target) bits.push("-> " + ev.target);
      if (ev.reason) bits.push(ev.reason);
      if (ev.fallback) bits.push("fallback " + ev.fallback);
      return bits.join("  ");
    }

    if (e.indexOf("action") === 0) {
      if (ev.action) bits.push(ev.action);
      if (ev.target) bits.push("-> " + ev.target);
      if (ev.result) bits.push("(" + ev.result + ")");
      return bits.join("  ");
    }

    if (e.indexOf("witness") === 0) {
      if (ev.implicated_device) bits.push(ev.implicated_device);
      if (ev.requested) bits.push("asked " + ev.requested);
      if (ev.acknowledged) bits.push("acked " + ev.acknowledged);
      if (ev.result) bits.push(ev.result);
      return bits.join("  ");
    }

    if (ev.message) bits.push(ev.message);
    return bits.join("  ");
  }

  function bump(ev) {
    counts.total++;
    if (ev.event === "reading.accepted") counts.accepted++;
    if (ev.event === "reading.rejected") counts.rejected++;
    if (ev.event === "decision.refused") counts.refused++;
    document.getElementById("count").textContent = counts.total;
    document.getElementById("accepted").textContent = counts.accepted;
    document.getElementById("rejected").textContent = counts.rejected;
    var r = document.getElementById("refused");
    if (r) r.textContent = counts.refused;
  }

  function render(ev) {
    var lane = laneFor(ev);
    var col = document.getElementById("lane-" + lane);
    if (!col) return;
    var card = document.createElement("div");
    card.className = "card " + clsFor(ev);
    var ts = ev.ts || new Date().toISOString();
    var det = detailFor(ev);
    card.innerHTML =
      '<div class="top"><span class="ev">' + esc(ev.event || "event") +
      ' <span class="code">' + esc(ev.code || "") + "</span></span>" +
      '<span class="t">' + relMs(ts) + "</span></div>" +
      '<div class="t">' + esc(ts) + " · seq " + esc(ev.seq !== undefined ? ev.seq : "?") + "</div>" +
      (det ? '<div class="detail">' + esc(det) + "</div>" : "");
    col.appendChild(card);
    col.scrollTop = col.scrollHeight;
    bump(ev);
  }

  function setConn(ok, text) {
    var el = document.getElementById("conn");
    el.textContent = text;
    el.style.color = ok ? "var(--green)" : "var(--red)";
  }

  function poll() {
    fetch("/v1/verdict?since=" + lastSeq)
      .then(function (r) { return r.json(); })
      .then(function (data) {
        (data.events || []).forEach(function (ev) {
          render(ev);
          if (typeof ev.seq === "number" && ev.seq > lastSeq) lastSeq = ev.seq;
        });
        document.getElementById("updated").textContent = new Date().toLocaleTimeString();
        setConn(true, "● live");
      })
      .catch(function () { setConn(false, "● offline"); });
  }

  function resetCounts() {
    counts = { total: 0, accepted: 0, rejected: 0, refused: 0 };
    ["count", "accepted", "rejected", "refused"].forEach(function (id) {
      var el = document.getElementById(id);
      if (el) el.textContent = "0";
    });
  }

  document.getElementById("clear").addEventListener("click", function () {
    ["twin", "guardian", "brain", "witness"].forEach(function (l) {
      document.getElementById("lane-" + l).innerHTML = "";
    });
    resetCounts();
  });

  // Show policy version in the header badge.
  fetch("/healthz").then(function (r) { return r.json(); }).then(function (h) {
    if (h.policy_version) document.getElementById("policy").textContent = "policy " + h.policy_version;
  }).catch(function () {});

  poll();
  setInterval(poll, POLL_MS);
})();
