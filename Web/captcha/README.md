# captcha

| Field | Value |
| --- | --- |
| CTF | z0d1akCTF 2026 Qualifiers |
| Category | Web Exploitation |
| Author | ludicrouslytrue |
| Points | 174 |
| Solves at time of solving | 42 |
| Flag | `zdk{53Ems_HuMAN_3NoU6H_7o_m3}` |

> Complete all four checks before time runs out.

## Executive Summary

The challenge is a "human verification" gate. A single attempt assigns four
independent mini-games — a file-sort, a pipe-rotation puzzle, a sliding-tile
puzzle, and a top-down **race lap** — that must all be completed within a
**10-second, server-enforced** window. Each check additionally enforces a
*minimum observation period*: a result cannot be submitted faster than it could
plausibly have been produced.

Solving the four games honestly is a dead end **by design**. The race lap's
observation period is equal to its own simulated duration (`ticks / hz`), and the
shortest lap the track physically permits is longer than the entire 10-second
window. No amount of driving skill can complete the race inside the deadline.

The intended solution is a **broken-authorization** flaw. The `verify` endpoint
returns a `proof` that is a **JWT scoped to the session/attempt** and asserts
`human: true` — it contains **no reference to which check was solved**. The
`accept` endpoint honours any valid proof for whatever check is named in the URL.
Therefore a single proof, minted by solving the *trivial* pipe puzzle once, can
be replayed to `accept` all four checks — the race lap included, without ever
driving it. `unlock` then returns the flag.

```
zdk{53Ems_HuMAN_3NoU6H_7o_m3}
```

The [exploit](solver/win.py) mints one proof and accepts all four checks,
finishing with time to spare:

```
[+ 1.45s] registered 4: ['cable-box', 'desktop-cleanup', 'tile-scramble', 'race-lap']
[+ 3.24s] setup done ws=4, 8.2s left
[+ 6.49s] minted proof via cable-box: 200 ok
[+ 7.20s] accept cable-box       200 completed=1
[+ 7.86s] accept desktop-cleanup 200 completed=2
[+ 8.66s] accept tile-scramble   200 completed=3
[+ 9.46s] accept race-lap        200 completed=4
[+10.20s] UNLOCK 200 {"ok": true, "flag": "zdk{53Ems_HuMAN_3NoU6H_7o_m3}"}
```

## Repository Contents

| Path | Purpose |
| --- | --- |
| [`solver/win.py`](solver/win.py) | **The exploit.** Mints one JWT proof, accepts all four checks, unlocks. Deps: `solvers.py`, `ws.py` only. |
| [`solver/solvers.py`](solver/solvers.py) | Honest solvers for the three tractable games (file-sort, cable-box, tile-scramble). |
| [`solver/ws.py`](solver/ws.py) | Minimal dependency-free WebSocket client (needed to satisfy `CHANNEL_SCOPE`). |
| [`solver/race.py`](solver/race.py) | Exact port of the server race physics + track clearance field + centre-line planner. |
| [`solver/plan.py`](solver/plan.py), [`solver/plan2.py`](solver/plan2.py) | Pure-pursuit racing-line controller (the honest-but-infeasible race path). |
| [`solver/png.py`](solver/png.py) | Minimal greyscale PNG writer for the analysis renders. |
| [`artifacts/proof-jwt-decoded.txt`](artifacts/proof-jwt-decoded.txt) | The captured `verify` proof, decoded — the crux of the bug. |
| [`artifacts/track_map.png`](artifacts/track_map.png) | Track collision mask with gates, finish and start marked. |
| [`artifacts/centerline_map.png`](artifacts/centerline_map.png) | Planned racing centre-line over the track. |
| [`artifacts/track-mask.bin`](artifacts/track-mask.bin) | The race collision bitmask (1 bpp, 800×541). |
| [`artifacts/centerline.json`](artifacts/centerline.json) | Precomputed centre-line waypoints. |
| [`artifacts/app.js`](artifacts/app.js), [`artifacts/race-core.js`](artifacts/race-core.js) | The client bundle and race physics module, for reference. |

Everything is standard-library Python 3; there are no third-party dependencies,
including for the WebSocket client.

> The challenge is an **instancer** (each launch gets a fresh
> `captcha-<id>.chals.z0d1ak.org` host with a short lifetime). Run the exploit
> against a live instance: `python3 solver/win.py captcha-<id>.chals.z0d1ak.org`.

## 1. Reconnaissance

The landing page is a small SPA served with a strict CSP. The interesting
signals are all in the client bundle [`app.js`](artifacts/app.js) and the API it
drives. `GET /api/state` describes the game:

```json
{
  "status": "waiting",
  "completed_checks": 0,
  "required_checks": 4,
  "minimum_wait_ms": 1000
}
```

`POST /api/check/start` begins an **attempt** and assigns one check. The response
carries the challenge type, its config, a `check_id`, a `channel_id`, and the
timing envelope:

```json
{
  "attempt_id": "attempt-…",
  "check_id":   "check-…",
  "channel_id": "channel-…",
  "challenge":  "cable-box",
  "claimed_at":            1787360787798,
  "minimum_complete_at":   1787360788798,   // claimed_at + 1000
  "deadline_at":           1787360797798,   // started_at + 10000
  "state": { "status": "running", "completed_checks": 0, "required_checks": 4 }
}
```

Reading the client, the full protocol is:

| Endpoint | Purpose |
| --- | --- |
| `POST /api/check/start` | Claim a check for a `client_id`; first call creates the attempt. |
| `GET  /api/check/live?channel=…` (WebSocket) | Live channel the check must be "connected" on. |
| `POST /api/checks/{id}/verify` | Submit a transcript; returns a `proof` on success. |
| `POST /api/checks/{id}/accept` | Consume a `proof`; increments `completed_checks`. |
| `POST /api/unlock` | Once all checks are complete, returns the flag. |
| `POST /api/session/restart` | Start a new attempt. |

Two structural facts fall out immediately and shape everything:

- **Four checks, one of each type, capacity-capped.** Registering more than four
  `client_id`s returns `CHECK_CAPACITY`. Every attempt contains exactly one
  `desktop-cleanup`, one `cable-box`, one `tile-scramble`, and one `race-lap`,
  all sharing a single `deadline_at`.
- **The 10-second deadline is enforced server-side.** Submitting after
  `deadline_at` returns `410 ATTEMPT_EXPIRED`, not merely a client-side timer.

## 2. The Three Tractable Checks

These are straightforward and are implemented in
[`solvers.py`](solver/solvers.py):

- **desktop-cleanup** — place each file in the folder whose `extensions` list
  accepts the file's extension. Transcript: `{placements:[{file_id,folder_id}]}`.
- **cable-box** — a "pipes/net" puzzle: choose a rotation `0..3` per tile so the
  whole grid is edge-consistent and every tile is powered from the source. Solved
  with backtracking + edge-matching pruning. Transcript: `{turns:[…]}`.
- **tile-scramble** — a 3×3 sliding puzzle solved with IDA* (Manhattan
  heuristic). Transcript: `{moves:[tileValue,…]}`.

Each is validated locally against the server's own rules before submission.

## 3. The Race Lap Is Deliberately Unwinnable

The fourth check, `race-lap`, loads a physics module,
[`race-core.js`](artifacts/race-core.js), a collision bitmask
(`/race/track-mask.bin`), and a gate layout. The transcript is a run-length
encoded input stream, `{runs:[[inputMask, ticks], …]}`, which the server
**re-simulates** with `replayRace()` and validates: the car must pass all gates
in order and cross the finish line, staying on the track (collision is a
point-in-mask test on the car's swept centre), and crucially
`finished_at_tick === total_ticks`.

To reason about it, I ported the physics exactly into
[`race.py`](solver/race.py), built a clearance field over the mask, routed a
centre-line through the gates with a clearance-weighted Dijkstra
([`artifacts/centerline_map.png`](artifacts/centerline_map.png)), and drove it
with a pure-pursuit controller ([`plan.py`](solver/plan.py),
[`plan2.py`](solver/plan2.py)). This reliably produces a **valid finishing lap**,
robust to the small per-attempt physics jitter — but at ~1000 ticks (~16 s of
simulated time).

Then the wall: submitting the lap returns

```
425 PHYSICALLY_IMPLAUSIBLE  "Check completed before the minimum observation period"
retry_at ≈ claimed_at + ticks/hz
```

The **minimum observation period equals the lap's own simulated duration**
(`ticks / hz`). You cannot submit a 16-second lap until 16 seconds of *real* time
have elapsed since the check was claimed — but the whole attempt lasts 10.

Could a faster lap fit? The track's centre-line is ~2545 px; at the maximum
speed of ~280 px/s the theoretical minimum lap is ~9.1 s (~545 ticks), and that
is unreachable because the hairpins force heavy braking. Even an optimal lap
would need ~9 s of real waiting, leaving no room to also complete the other
three checks and `unlock` before the 10-second deadline. **The race cannot be
beaten legitimately** — which is the hint that the win lies elsewhere.

## 4. The Vulnerability: an Unbound Authorization Token

Instead of driving the lap, I looked at what `verify` actually hands back. On a
successful `verify` the `proof` field is a **JWT**
([decoded here](artifacts/proof-jwt-decoded.txt)):

```json
// header
{ "alg": "HS256", "typ": "JWT" }
// payload
{
  "iss":   "captcha",
  "sub":   "session:attempt-b4b46e6f15d0616e7618be6d",
  "aud":   "human-verification",
  "human": true,
  "iat":   1787366168,
  "exp":   1787366176            // iat + 8s
}
```

The token proves one thing — *this session has passed a human check* — and is
scoped to the **attempt**, via `sub`. It carries **no `check_id`**. Nothing in
the token ties it to the specific game that produced it.

The `accept` endpoint takes `{proof}` and credits the check named in the *URL*.
Because it never checks that the proof came from *that* check's own `verify`, a
proof minted anywhere is accepted everywhere. The decisive experiment: verify
the easy `cable-box` check, then POST its proof to the **race-lap** `accept`:

```
verify  cable-box            -> 200, proof = <JWT>
accept  race-lap  {proof}    -> 200, completed_checks = 1     # race credited, never driven
```

That is the whole bug: **verification is per-check, but the proof of humanity is
per-session and interchangeable.** One human check unlocks all of them.

(There is one guard that must still be satisfied: `verify`/`accept` require a
live WebSocket "connected" on the check's `channel_id`, or they return
`403 CHANNEL_SCOPE`. That is a scoping check on the *channel*, not the proof, and
is met simply by opening the socket — hence the small WebSocket client in
[`ws.py`](solver/ws.py).)

## 5. Exploitation

[`win.py`](solver/win.py) performs the end-to-end attack, structured to fit the
10-second window comfortably (the flow needs only one `verify`):

1. From the `waiting` state, `POST /api/check/start` four times to populate one
   attempt with all four checks.
2. Open a WebSocket to `/api/check/live?channel=…` for each check (in parallel)
   to satisfy `CHANNEL_SCOPE`.
3. Wait out the 1-second `minimum_complete_at`, then `verify` the **cable-box**
   puzzle once to mint a `human: true` JWT.
4. Replay that single proof to `POST /api/checks/{id}/accept` for **all four**
   checks. `completed_checks` climbs 1 → 2 → 3 → 4.
5. `POST /api/unlock` → flag.

```console
$ python3 solver/win.py captcha-<id>.chals.z0d1ak.org
[+ 1.45s] registered 4: ['cable-box', 'desktop-cleanup', 'tile-scramble', 'race-lap']
[+ 3.24s] setup done ws=4, 8.2s left
[+ 6.49s] minted proof via cable-box: 200 ok
[+ 7.20s] accept cable-box       200 completed=1
[+ 7.86s] accept desktop-cleanup 200 completed=2
[+ 8.66s] accept tile-scramble   200 completed=3
[+ 9.46s] accept race-lap        200 completed=4
[+10.20s] UNLOCK 200 {"ok": true, "flag": "zdk{53Ems_HuMAN_3NoU6H_7o_m3}"}
```

```
zdk{53Ems_HuMAN_3NoU6H_7o_m3}
```

The flag — *"seems human enough to me"* — is a wink at the flaw: a single
"human" assertion is trusted for every check.

## 6. Root Cause and Fix

The proof-of-work is sound (each game is validated, the observation period is
enforced), but the **binding** between the proof and the work is missing.

- **Root cause:** the `verify` JWT authorizes the *session* (`sub =
  session:attempt-…`, `aud = human-verification`) rather than the *task*. `accept`
  trusts any session-valid proof for any `check_id`.
- **Fix:** bind the proof to the exact work it attests. Include the `check_id`
  (and challenge type / transcript hash) as a claim in the JWT, and have `accept`
  reject a proof whose `check_id` ≠ the check being accepted. Making proofs
  single-use per check would harden it further.

## Lessons

- **When one path is provably impossible, that is the hint.** The race lap's
  observation period exceeds the attempt window by construction — a signal that
  the intended solution bypasses the games rather than beating them.
- **Read the token, not just the flow.** The proof looked opaque; base64-decoding
  the JWT exposed a session-scoped claim with no task binding.
- **Authentication ≠ authorization.** A valid "you are human" proof was allowed
  to authorize *any* action, because the action it was minted for was never
  recorded in it.
