# Guardian `INTERFACE.md` — integration card (v2.0)

**Layer:** Guardian (trust layer) · **Package:** AEGIS LOOP · **Protocol:** NGSI v2 (broker) + REST/JSON
**Status:** v2.0, 8 Nov 2026 — adapted to the triplet's Orion contract · **Policy:** `v1.0`

> The Guardian's job: **mark untrustworthy data within seconds, say why, and never let a lying
> sensor authorize an actuator.** "Every action carries its own proof."

---

## 1. The triplet interface (what the Twin and the Brain actually use)

The layers never call each other. They share state through the Orion broker.

```
Twin ──writes sensor entities──▶ ORION ◀──GET /v2/entities/{id}── Guardian
                                   ▲                                  │
                                   └──── GET /verdicts ───────────────┴──▶ Brain
```

### In: NGSI v2 from the Orion broker (Twin → Guardian)

The Twin does not post to us. It writes NGSI entities to
`https://smartopia.polytecsousse.dev/orion-filter/orion-1`, and the Guardian **polls**
`GET /v2/entities/{id}` for every sensor in its device list once per tick (5 s by default,
matching the Twin's step).

```bash
curl -XPOST localhost:8090/v1/ngsi/poll -H 'content-type: application/json' -d '{}'
# {"broker":"smartopia.polytecsousse.dev","devices":14,"frames":26,"accepted":26,
#  "results":[...],"verdicts":{...}}
```

The device list defaults to the shipped `orion_devices.json` (a snapshot of
`twin/config.json`) and can point at any Twin-style config file:

```bash
GUARDIAN_DEVICES_CONFIG=/path/to/twin/config.json      # env override
# or per call:  -d '{"config": "../twin/config.json"}'
```

The attribute mapping lives in `ngsi.yaml` — **data, not code**. Adding a device or renaming a
broker attribute is a config edit:

| NGSI entity | zone | attribute → `observed_property` | unit |
|---|---|---|---|
| `us-a-traf-01..03` | `ZONE-A` | `congestionLevel` → `congestion` | % |
| | | `avgSpeed` → `vehicle_speed` | km/h |
| | | `vehicleCount` → `traffic_camera` | count |
| `us-b-bldg-01` | `ZONE-B` | `smokeLevel` → `fire_smoke` | ppm |
| | | `temperature` → `temperature` | °C |
| | | `occupancyCount` → `building_occupancy` | people |
| `us-c-cam-01` | `ZONE-C` | `dumpingDetected` → `camera_alert` | 0/1 |
| | | `confidence` → `camera_confidence` | 0–1 |
| `us-c-bin-01..02` | `ZONE-C` | `fillLevel` → `fill_level` | % |

Two deliberate choices a reviewer should hear from us first:

* **`occupancy` is NOT mapped** on traffic entities. The Twin derives it from the same generator
  as `congestionLevel` (within ±2 % of it), so mapping both would feed one physical quantity into
  a single property's history twice and manufacture false agreement.
* **Text attributes are skipped** (`status`, `message`): they carry no physics to score, and
  guessing at them would produce a confidently wrong verdict.

**Provenance, stated honestly.** The Orion Broker Filter authenticates the *writer* with K1/K2, so
a value that arrives over the broker was authenticated by the platform, not signed per frame. We
record `provenance.firmware` from the entity type and a `cal` marker of `ngsi-orion:<attribute>`,
and we do **not** fabricate an HMAC we cannot compute. With `verify_signatures: true` a broker
frame is refused as unsigned — correct behaviour, and why broker ingest runs with that gate off.
This is a known, bounded limitation, not a hidden one.

### Out: `GET /verdicts` (Guardian → Brain)

The Twin's own mock Brain reads `{device: {verdict, reason, checked}}` from
`http://localhost:8090/verdicts`. We publish **the same three keys**, plus the evidence behind
them, so a Brain written against the mock works unchanged:

```bash
curl localhost:8090/verdicts
```
```json
{
  "us-b-bldg-01": {
    "verdict": "TRUSTED",
    "reason": "OK",
    "checked": "20:08:59",
    "trust": 0.94,
    "zone": "ZONE-B",
    "disposition": "TRUSTED",
    "properties": {
      "fire_smoke":   {"verdict": "TRUSTED", "trust": 0.94, "disposition": "TRUSTED", "reasons": [], "age_s": 0.4},
      "temperature":  {"verdict": "TRUSTED", "trust": 0.94, "disposition": "TRUSTED", "reasons": [], "age_s": 0.4}
    },
    "evidence_digest": "sha256:528f4e1f…"
  },
  "us-a-traf-02": {"verdict": "OFFLINE", "reason": "COMM_LOSS", "checked": "20:09:04", "trust": 0.0, "zone": "ZONE-A"}
}
```

Rules that define the feed:

| Rule | Behaviour | Why |
|---|---|---|
| `verdict` | `TRUSTED` / `UNTRUSTED` / `OFFLINE` | exactly the Twin's mock vocabulary; `SUSPECT`/`RESTRICT`/`MALICIOUS` → `UNTRUSTED` |
| `disposition` | the device's worst property disposition; `RESTRICT` on an OFFLINE row | additive detail for a reader who wants the stage-E word |
| per device | the **worst** property decides | malice in one attribute is not healed by virtue in another |
| `reason` | stable codes, comma-joined (`CONFLICT`, `RATE_ANOMALY`, `STEADY_ANOMALY`, `JAM`, `COMM_LOSS`, `STALE`, `OUT_OF_RANGE`, `DRIFT`, `TAMPER`, `SPOOF`, `IMPLAUSIBLE`, `REPLAY`) or `OK` | the Brain can branch on them without parsing prose |
| `checked` | `HH:MM:SS` local time of the verdict that produced the row | human-readable on the timeline |
| staleness | no fresh verdict for `orion.stale_after_s` (20 s ≈ 4 polls) → `OFFLINE` / `COMM_LOSS` | the broker keeps the last entity of a dead sensor, so only freshness reveals it (g2) |
| inventory | a mapped device never yet read also appears as `OFFLINE` / `COMM_LOSS` | honest about the edge; never invents a verdict |
| actuators | devices with no sensor physics get **no row** | a traffic light has no trustworthiness to report |

### Out (optional): `TrustVerdict` entities written back to Orion

The root contract asks the Guardian to *write* its verdicts (`INTEGRATION.md`: "verdict (format to
confirm)"). We confirm it here, and it is **off by default** because it needs the Guardian's own
K1/K2 keys:

```bash
GUARDIAN_PUBLISH_VERDICTS=true GUARDIAN_POLL_SECONDS=5 make demo
```

| Field | Value |
|---|---|
| entity id | `<device>-verdict` (e.g. `us-b-bldg-01-verdict`) |
| entity type | `TrustVerdict` |
| attributes | `verdict`, `reason`, `trust`, `zone`, `checked` |
| write | `PATCH /v2/entities/{id}/attrs?elementid={id}&type=TrustVerdict&k1=…&k2=…`, `POST` if absent |
| keys | `guardian/guardian_secrets.json` — `{"devices": {"us-b-bldg-01-verdict": {"k1": "…", "k2": "…"}}}`, **gitignored** |
| text safety | `< > " ' = ; ( )` are stripped from every text attribute (the broker answers 400 otherwise) |

Write-back is **fail-soft**: a refused write is counted on `/orion/status` and never stops the
poller or the `/verdicts` feed. Until keys exist, `/verdicts` is the delivery path — which is what
the Twin's mock Brain already consumes.

### The answers the shared Test Book expects

| Id | Twin's pass criterion | Our verdict | How |
|---|---|---|---|
| **n1** calm day | nothing happens | every sensor `TRUSTED` | no flags |
| **a1** roads 1 & 2 jam | Brain relieves the traffic | `TRUSTED` | real ramp + a sibling road confirms it |
| **b1** fire | Brain may sound the alarm | `TRUSTED` | smoke and heat rise together |
| **c1** bin fills to 97 % | Brain may create the task | `TRUSTED` | a filling bin is the incident, not an attack |
| **g1** smoke 400 ppm at 22 °C | `us-b-bldg-01` is UNTRUSTED | `UNTRUSTED` / `CONFLICT` | smoke without heat |
| **g2** stuck + dead | both flagged | stuck `UNTRUSTED` / `JAM`, dead `OFFLINE` / `COMM_LOSS` | repeated values; no fresh verdicts |
| **g3** fake jam | `us-a-traf-03` is UNTRUSTED | `UNTRUSTED` / `STEADY_ANOMALY` | pinned ceiling, no independent witness |
| **m1** fire + fake jam | zone split | building `TRUSTED`, fake road `UNTRUSTED` | both rules at once |
| **d1** Brain down | sensors still trustworthy | building `TRUSTED` | trust does not depend on the Brain |

Asserted in `tests/test_ngsi_triplet.py` and `tests/test_orion.py`; reproduce end to end with
`make checks`.

---

## 2. Discovery — `GET /describe`

Every layer exposes this so partners never hard-code. Validated by `shared/schema/describe.json`:

```json
{
  "layer": "guardian", "version": "1.0.0", "protocol": "rest+json",
  "optional_faces": ["mcp-tools"],
  "endpoints": {
    "readings": "POST /v1/readings", "passport": "POST /v1/passport",
    "verdict": "GET /v1/verdict/{passport_id}", "witness": "POST /v1/witness",
    "healthz": "GET /healthz"
  },
  "auth": "hmac-sha256 header X-Signature over body; key via config",
  "accepts_sensor_types": ["air_quality","emergency_call","fire_smoke","flow","gps",
                           "power_load","rain","traffic_camera","water_level"],
  "emits_dispositions": ["TRUSTED","SUSPECT","MALICIOUS","RESTRICT"],
  "max_latency_s": 10.0, "policy_version": "v1.0"
}
```

`GET /healthz` → `{status, layer, version, policy_version, uptime_s}`.

`GET /orion/status` → the broker face in one read, so a reviewer can confirm wiring without tools:

```json
{"enabled": true, "broker": "smartopia.polytecsousse.dev",
 "poll_seconds": 5.0, "stale_after_s": 20.0,
 "devices_config": "orion_devices.json (shipped snapshot)", "mapped_kinds": ["bin","building","camera","traffic"],
 "poller": {"alive": true, "cycles": 41, "last_cycle_at": "20:09:04",
            "last_summary": {"devices": 14, "frames": 26, "accepted": 26, "rejected": 0,
                             "unreachable": [], "published": 0, "publish_skipped": 7},
            "errors": []},
 "writer": null}
```

---

## 3. Endpoints (in / out)

| Endpoint | Direction | Purpose | Status |
|---|---|---|---|
| `GET  /verdicts` | **out** (to Brain) | The device verdict feed above. | ✅ live |
| `GET  /orion/status` | out | Poller health, broker, mapping, write-back counters. | ✅ live |
| `POST /v1/ngsi/poll` | **in** (manual) | One broker read → pipeline → per-frame acks + verdicts. | ✅ live |
| `POST /v1/readings` | **in** (frame transport) | Accept a reading or `{"readings":[...]}`. Schema-validated, deduped, device-gated, audited. Returns per-reading `{accepted, code, reading_id, event_id}`. | ✅ live |
| `GET  /v1/verdict?since=<seq>` | out | Append-only event stream (hash-chained). Powers the live timeline. | ✅ live |
| `GET  /v1/verdict/{passport_id}` | out | Look up one stored verdict/passport. | ✅ live |
| `POST /v1/passport` | **out** (to Brain/Twin) | **Evidence Passport** for an `evidence_digest`. SUSPECT/RESTRICT/MALICIOUS passports never carry `full`. | ✅ live |
| `POST /v1/witness` | **in** (from Twin) | Effect Witness; a MISMATCH decays the device's `history` factor, 3 consecutive quarantine it. | ✅ live |
| `GET  /ui/` | out (demo) | Live timeline screen: reading → verdict → decision → action, with timestamps. | ✅ live |

---

## 4. Message examples (one of each)

**Reading — Twin → Guardian** (`shared/schema/reading.json`)
```json
{"batch_id":"b-42","reading_id":"r-001","sensor_id":"river-gauge-1","zone":"Z-RIVER_UNDERPASS",
 "observed_property":"water_level","phenomenon_time":"2026-10-20T10:03:11.900Z",
 "result":{"value":0.82,"unit":"m"},
 "provenance":{"firmware":"1.4","cal":"CAL-07","seq":100},
 "digest":"sha256:<64hex>","signature":"ed25519:<b64>"}
```
Response: `{"received":1,"accepted":1,"results":[{"accepted":true,"code":"ACCEPTED","reading_id":"r-001","event_id":1}]}`

**Evidence Passport — Guardian → Brain/Twin** (`shared/schema/passport.json`) — live T5 values
```json
{"passport_id":"psp-181a35ce","issued_at":"2026-10-25T11:16:12.000Z","ttl_s":6,"zone":"Z-PORT",
 "disposition":"SUSPECT","trust":0.544,"reason_codes":["CONFLICT","RATE_ANOMALY"],
 "evidence_digest":"sha256:<64hex>","source_ids":["port-gauge-1","port-rain-1","port-cam-1"],
 "policy_version":"v1.0","allowed_actions":["reversible","precautionary"],
 "conditions":["require_second_source","prefer_precautionary"],"signature":"hmac-sha256:<hex>"}
```
> A SUSPECT/RESTRICT/MALICIOUS passport never carries `full` — the Brain's `valve.full_open` is
> refused with a recorded reason; `barrier.partial_close` (class `reversible`) remains permitted.

**Proof-Carrying Action — Brain → Twin** (`shared/schema/action.json`)
```json
{"action_id":"a-900","idempotency_key":"a-900","passport_id":"psp-042",
 "evidence_digest":"sha256:<64hex>","target":"valve-1","target_version":"v3",
 "action":"valve.partial_close","params":{"fraction":0.3}}
```
> The **Twin** re-verifies `passport_id` + `evidence_digest` + `action ∈ allowed_actions` + `ttl`
> before acting, else denies with a stable code.

**Effect Witness — Twin → Guardian** (`shared/schema/witness.json`)
```json
{"action_id":"a-900","requested":"pump.on","acknowledged":"applied",
 "observed":{"flow_sensor":"flat"},"result":"MISMATCH","implicated_device":"pump-1"}
```

---

## 5. Configuration (no hard-coded hosts)

All endpoints live in `guardian/config.yaml` and are overridable by env:

```yaml
orion:
  enabled: true
  base_url: "https://smartopia.polytecsousse.dev/orion-filter/orion-1"
  devices_config: ""          # "" -> shipped orion_devices.json snapshot
  poll_seconds: 5             # one tick = the Twin's 5 s step
  stale_after_s: 20           # ~4 polls without fresh verdicts -> OFFLINE
  publish_enabled: false      # TrustVerdict write-back (needs K1/K2)
```

```bash
export GUARDIAN_BROKER_URL="https://another-broker.example/orion-1"
export GUARDIAN_DEVICES_CONFIG="/path/to/twin/config.json"
export GUARDIAN_POLL_SECONDS=5
export GUARDIAN_STALE_AFTER_S=20
export GUARDIAN_PORT=8090
```

Then, on stage: `docker compose up -d guardian`.

## 6. Authentication

- **Inbound frames:** HMAC-SHA256 header `X-Signature` over the raw body; key from env
  (`GUARDIAN_HMAC_KEY`) or `keys/dev_keys.json`. Enabled with `GUARDIAN_VERIFY_SIGNATURES=true`.
- **Broker:** K1/K2 per device. Reads of public devices need no key; the Guardian holds no Twin
  secrets. Write-back (`TrustVerdict`) needs the Guardian's **own** K1/K2, never committed.
- **Dev:** signature verification is **off** by default so partners integrate fast.
- Secrets are never committed (`.gitignore`: `secrets.json`, `*_secrets.json`, `.env`, `keys/*.pem`).

## 7. Contracts & guarantees

- **Schemas** live in `shared/schema/*.json` (Draft 2020-12) and are enforced at the boundary.
  Invalid → `400` + a stable code (`SCHEMA_INVALID`, `DUPLICATE`, `UNKNOWN_DEVICE`, `STALE`),
  never a crash.
- **Idempotency:** readings deduped by `reading_id` (= `device:attribute:timestamp` from the
  broker, so a re-polled unchanged entity is a duplicate by construction); actions by
  `idempotency_key`.
- **Audit:** every event appended to a hash-chained `audit.jsonl` (tamper-evident, replayable).
- **Latency:** a broker reading is scored within the tick that read it; the device face is derived
  from in-memory verdicts, so `GET /verdicts` is O(devices), not O(history).
- **Determinism:** the same entity sequence produces the same verdicts; wall-clock is stamped,
  never scored.
- **Graceful degradation:** an unreachable broker or one bad device never stops the poller — the
  cycle is recorded, the next tick retries, and `/orion/status` reports what was unreachable.

## 8. Run it standalone (no platform account)

```bash
make setup && make checks        # nine scenarios offline -> logs/ + PASS/FAIL
make demo                        # :8090/verdicts against the real broker config
make mock-orion                  # a fake broker on :8025, then:
curl -XPOST localhost:8025/scenario -d '{"name":"g3"}'
```

## 9. Integration checklist for partners

- [ ] **Twin:** keep publishing the sensor entities listed above (we poll them; nothing to call).
- [ ] **Twin:** if you want push semantics, POST frames to `/v1/readings` — same pipeline.
- [ ] **Brain:** read `GET /verdicts`; treat `UNTRUSTED` as "do not act on this alone" and
      `OFFLINE` as "no data", never as "normal".
- [ ] **Brain:** cite `evidence_digest` when you want the signed passport behind a decision.
- [ ] Both: expose `GET /describe`; keep endpoints in config, not code.

*End of INTERFACE.md v2.0. Bump the version on any breaking change; `policy_version` is stamped on every passport.*
