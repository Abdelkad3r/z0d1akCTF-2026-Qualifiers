#!/usr/bin/env python3
"""Reconstruct the Unrotated incident report from the supplied evidence."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import ipaddress
import json
import re
import shlex
import shutil
import socket
import sqlite3
import ssl
import subprocess
import tarfile
import tempfile
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path


DEFAULT_HOST = "unrotated-e94e4c439400.chals.z0d1ak.org"
DEFAULT_PORT = 1337
FLAG_PATTERN = re.compile(r"zdk\{[^}\r\n]+\}")

# The recovered frame explicitly says connector continuity is authoritative.
# These six connections are transcribed from route-patch-panel.png.
PATCH_PANEL = {
    "LEAD-A": "SOCKET-4",
    "LEAD-B": "SOCKET-1",
    "LEAD-C": "SOCKET-5",
    "LEAD-D": "SOCKET-2",
    "LEAD-E": "SOCKET-6",
    "LEAD-F": "SOCKET-3",
}

# The external owner identifies the relevant route profile. The other two
# cached profiles are inventory and telemetry; neither describes a forecast
# survey execution.
OWNER_PROFILE = {
    "Tethys Forecast Cooperative": "survey",
    "Hull telemetry partner": "telemetry",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def format_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle))


def unpack_handout(archive: Path, destination: Path) -> tuple[Path, str]:
    with zipfile.ZipFile(archive) as outer:
        inner_names = [name for name in outer.namelist() if name.endswith(".zip")]
        if len(inner_names) != 1:
            raise ValueError("expected exactly one nested evidence ZIP")
        inner_data = outer.read(inner_names[0])

    with zipfile.ZipFile(io.BytesIO(inner_data)) as inner:
        inner.extractall(destination)

    roots = [path for path in destination.iterdir() if path.is_dir()]
    if len(roots) != 1:
        raise ValueError("could not identify the extracted evidence root")
    return roots[0], sha256(inner_data)


def verify_checksums(evidence: Path) -> list[tuple[str, str]]:
    verified: list[tuple[str, str]] = []
    for line in (evidence / "SHA256SUMS.txt").read_text().splitlines():
        expected, relative = line.split(maxsplit=1)
        relative = relative.lstrip("* ")
        actual = sha256((evidence / relative).read_bytes())
        if actual != expected:
            raise ValueError(f"checksum mismatch: {relative}")
        verified.append((relative, actual))
    return verified


def parse_gateway(path: Path) -> list[dict[str, str]]:
    parsed = []
    for line in path.read_text().splitlines():
        fields = {}
        for token in shlex.split(line):
            key, value = token.split("=", 1)
            fields[key] = value
        parsed.append(fields)
    return parsed


def decode_journal(path: Path) -> list[dict[str, str]]:
    native = shutil.which("journalctl")
    if native:
        command = [native, f"--file={path}", "--no-pager", "-o", "json"]
    elif shutil.which("docker"):
        mount = f"{path.resolve()}:/evidence/system.journal:ro"
        command = [
            "docker",
            "run",
            "--rm",
            "-v",
            mount,
            "archlinux:latest",
            "journalctl",
            "--file=/evidence/system.journal",
            "--no-pager",
            "-o",
            "json",
        ]
    else:
        raise RuntimeError("journalctl is unavailable (install it or use Docker)")

    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return [json.loads(line) for line in result.stdout.splitlines() if line]


def replay_cast(path: Path) -> list[str]:
    lines = path.read_text().splitlines()
    header = json.loads(lines[0])
    width, height = header["width"], header["height"]
    screen = [[" "] * width for _ in range(height)]
    row = col = 0

    for encoded in lines[1:]:
        _delay, stream, output = json.loads(encoded)
        if stream != "o":
            continue
        index = 0
        while index < len(output):
            if output[index] == "\x1b":
                match = re.match(r"\x1b\[(\d*);?(\d*)([A-Za-z])", output[index:])
                if match is None:
                    index += 1
                    continue
                first = int(match.group(1) or 1)
                second = int(match.group(2) or 1)
                command = match.group(3)
                if command == "H":
                    row, col = first - 1, second - 1
                elif command == "J" and first == 2:
                    screen = [[" "] * width for _ in range(height)]
                    row = col = 0
                index += len(match.group(0))
                continue

            if 0 <= row < height and 0 <= col < width:
                screen[row][col] = output[index]
            col += 1
            index += 1

    return ["".join(line).rstrip() for line in screen]


def cast_routes(screen: list[str]) -> dict[str, dict[str, str]]:
    result = {}
    pattern = re.compile(
        r"^(watch-[0-9a-f]+)\s+(\S+)\s+(pel-\d+)\s+(LEAD-[A-F])\s+(\S+)$"
    )
    for line in screen:
        match = pattern.match(line)
        if match:
            screen_ref, console, channel, lead, state = match.groups()
            result[screen_ref] = {
                "console_slot": console,
                "channel": channel,
                "lead": lead,
                "state": state,
            }
    return result


def oci_routes(path: Path) -> list[dict[str, str]]:
    recovered = []
    with tarfile.open(path) as image:
        index = json.load(image.extractfile("index.json"))
        for descriptor in index["manifests"]:
            cache = descriptor["annotations"]["org.opencontainers.image.ref.name"]
            manifest_digest = descriptor["digest"].split(":", 1)[1]
            manifest = json.load(
                image.extractfile(f"blobs/sha256/{manifest_digest}")
            )
            config_digest = manifest["config"]["digest"].split(":", 1)[1]
            config = json.load(image.extractfile(f"blobs/sha256/{config_digest}"))
            route = None
            route_layer = None

            # Inspect historical layers directly. The final layer whiteouts the
            # route from the merged view but cannot remove these earlier bytes.
            for layer_number, layer in enumerate(manifest["layers"], 1):
                digest = layer["digest"].split(":", 1)[1]
                payload = image.extractfile(f"blobs/sha256/{digest}").read()
                with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as layer_tar:
                    for member in layer_tar.getmembers():
                        if member.name.endswith("/route.json"):
                            route = json.load(layer_tar.extractfile(member))
                            route_layer = digest

            if route is None:
                raise ValueError(f"no historical route.json found for {cache}")
            recovered.append(
                {
                    "cache": cache,
                    "created": config["created"],
                    "layer": route_layer or "",
                    **{key: str(value) for key, value in route.items()},
                }
            )
    return recovered


def network_contains(cidr: str, address: str) -> bool:
    return ipaddress.ip_address(address) in ipaddress.ip_network(cidr)


def submit_report(endpoint: str, report: list[str]) -> str:
    if ":" in endpoint:
        host, raw_port = endpoint.rsplit(":", 1)
        port = int(raw_port)
    else:
        host, port = endpoint, DEFAULT_PORT

    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=15) as raw:
        with context.wrap_socket(raw, server_hostname=host) as connection:
            connection.settimeout(10)
            buffer = b""
            for index, answer in enumerate(report, 1):
                marker = f"report[{index}]> ".encode()
                while marker not in buffer:
                    chunk = connection.recv(65536)
                    if not chunk:
                        raise ConnectionError(f"service closed before prompt {index}")
                    buffer += chunk
                buffer = buffer.split(marker, 1)[1]
                connection.sendall(answer.encode() + b"\n")

            response = buffer
            while True:
                try:
                    chunk = connection.recv(65536)
                except TimeoutError:
                    break
                if not chunk:
                    break
                response += chunk
    return response.decode(errors="replace")


def write_artifacts(
    output: Path,
    archive: Path,
    inner_hash: str,
    verified: list[tuple[str, str]],
    screen: list[str],
    journal: list[dict[str, str]],
    route_rows: list[dict[str, str]],
    timeline: list[tuple[str, str, str]],
    route_chain: list[str],
    report: list[str],
) -> None:
    output.mkdir(parents=True, exist_ok=True)
    hashes = [f"{sha256(archive.read_bytes())}  {archive.name}"]
    hashes.append(f"{inner_hash}  unrotated-evidence.zip")
    hashes.extend(f"{digest}  {relative}" for relative, digest in verified)
    (output / "evidence-hashes.txt").write_text("\n".join(hashes) + "\n")

    visible = [line for line in screen if line]
    (output / "watch-console.txt").write_text("\n".join(visible) + "\n")

    with (output / "oci-routes.csv").open("w", newline="") as handle:
        fields = [
            "cache",
            "created",
            "profile",
            "screen_ref",
            "console_slot",
            "channel",
            "layer",
        ]
        writer = csv.DictWriter(
            handle,
            fieldnames=fields,
            extrasaction="ignore",
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(route_rows)

    relevant_messages = []
    for event in journal:
        message = event.get("MESSAGE", "")
        if (
            "OR-7312" in message
            or "pid=24144" in message
            or "proc-7ae13f0c35d8" in message
        ):
            timestamp = datetime.fromtimestamp(
                int(event["__REALTIME_TIMESTAMP"]) / 1_000_000,
                tz=timezone.utc,
            )
            relevant_messages.append(f"{format_time(timestamp)} {message}")
    (output / "journal-relevant.txt").write_text(
        "\n".join(relevant_messages) + "\n"
    )

    with (output / "incident-timeline.csv").open("w", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(["timestamp_utc", "source", "finding"])
        writer.writerows(timeline)

    (output / "route-chain.txt").write_text("\n".join(route_chain) + "\n")
    (output / "incident-report.txt").write_text(
        "\n".join(f"report[{i}]={value}" for i, value in enumerate(report, 1))
        + "\n"
    )


def investigate(evidence: Path, journal_required: bool = True) -> dict[str, object]:
    rotation = rows(evidence / "identity/rotation_manifest.csv")
    partners = rows(evidence / "identity/partner_registry.csv")
    partner_credentials = {row["credential_label"] for row in partners}
    stale = [
        row
        for row in rotation
        if not row["completed_utc"] and row["label"] not in partner_credentials
    ]
    if len(stale) != 1:
        raise ValueError(f"expected one unexplained unrotated credential, got {stale}")
    credential = stale[0]

    gateway = parse_gateway(evidence / "gateway/access.log")
    accesses = [
        row
        for row in gateway
        if row.get("token_fp") == credential["fingerprint"]
        and row.get("status") == "200"
    ]
    first_access = min(accesses, key=lambda row: parse_time(row["ts"]))

    audit = rows(evidence / "collaboration/audit.csv")
    creates = [
        row
        for row in audit
        if row["actor_uuid"] == credential["principal_uuid"]
        and row["action"] == "principal_create"
        and row["result"] == "success"
    ]
    if len(creates) != 1:
        raise ValueError("could not uniquely identify the persistence principal")
    persistence_uuid = creates[0]["target"].rsplit("/", 1)[1]
    grants = [
        row
        for row in audit
        if row["actor_uuid"] == credential["principal_uuid"]
        and row["action"] == "group_member_add"
        and row["target"].endswith("/" + persistence_uuid)
    ]
    if len(grants) != 1:
        raise ValueError("could not identify the persistence privilege grant")

    connection = sqlite3.connect(evidence / "collaboration/directory.db")
    try:
        row = connection.execute(
            "SELECT account_name FROM principals WHERE principal_uuid = ?",
            (persistence_uuid,),
        ).fetchone()
    finally:
        connection.close()
    if row is None:
        raise ValueError("persistence UUID is absent from directory.db")
    persistence_name = row[0]

    change_match = re.search(r"change_ref=(CHG-\d+)", creates[0]["detail"])
    if change_match is None:
        raise ValueError("persistence event has no change reference")
    change_id = change_match.group(1)
    ledger = rows(evidence / "governance/change_ledger.csv")
    cover = next(row for row in ledger if row["change_id"] == change_id)
    if cover["subject_uuid"] == persistence_uuid:
        raise ValueError("change record actually authorizes the persistence principal")

    jobs = [
        row
        for row in audit
        if row["actor_uuid"] == persistence_uuid
        and row["action"] == "runner_job_submit"
        and row["result"] == "accepted"
    ]
    if len(jobs) != 1:
        raise ValueError("could not uniquely identify the delegated runner job")
    job_event = jobs[0]
    job = job_event["target"].rsplit("/", 1)[1]
    job_time = parse_time(job_event["timestamp_utc"])

    journal: list[dict[str, str]] = []
    try:
        journal = decode_journal(evidence / "host/system.journal")
    except (RuntimeError, subprocess.CalledProcessError):
        if journal_required:
            raise
    journal_job = [event for event in journal if job in event.get("MESSAGE", "")]
    if journal and not journal_job:
        raise ValueError(f"{job} is absent from the system journal")

    firewall = rows(evidence / "network/firewall.csv")
    approved = rows(evidence / "network/approved_egress.csv")
    inventory = rows(evidence / "network/host_inventory.csv")
    host_by_address = {row["address"]: row for row in inventory}
    collab_address = next(
        row["address"] for row in inventory if row["hostname"] == "collab-app-01"
    )

    window = [
        row
        for row in firewall
        if row["source"] == collab_address
        and job_time
        <= parse_time(row["timestamp_utc"])
        <= job_time + timedelta(minutes=10)
    ]

    def approved_record(flow: dict[str, str]) -> dict[str, str] | None:
        for record in approved:
            ports = {part.strip() for part in record["ports"].split(";")}
            destination_matches = network_contains(
                record["destination_cidr"], flow["destination"]
            )
            if destination_matches and flow["destination_port"] in ports:
                return record
        return None

    rendezvous_candidates = [
        flow
        for flow in window
        if flow["action"] == "allow"
        and flow["destination"] not in host_by_address
        and approved_record(flow) is None
    ]
    if len(rendezvous_candidates) != 1:
        raise ValueError(
            f"unexpected unapproved rendezvous set: {rendezvous_candidates}"
        )
    rendezvous = rendezvous_candidates[0]
    process_ref = rendezvous["process_ref"]

    process_flows = [row for row in window if row["process_ref"] == process_ref]
    partner_flows = [row for row in process_flows if approved_record(row) is not None]
    if len(partner_flows) != 1:
        raise ValueError(
            "could not identify the compromised process's partner cover flow"
        )
    partner_record = approved_record(partner_flows[0])
    assert partner_record is not None
    profile = OWNER_PROFILE[partner_record["owner"]]

    follow_ons = [
        row
        for row in process_flows
        if row["action"] == "deny"
        and row["destination"] in host_by_address
        and host_by_address[row["destination"]]["environment"] == "non-production"
    ]
    if len(follow_ons) != 1:
        raise ValueError("could not identify the non-production follow-on attempt")
    follow_on = follow_ons[0]
    follow_on_host = host_by_address[follow_on["destination"]]["hostname"]

    routes = oci_routes(evidence / "host/runner-cache.oci.tar")
    matching_routes = [route for route in routes if route["profile"] == profile]
    if len(matching_routes) != 1:
        raise ValueError(f"no unique OCI route for profile {profile}")
    route = matching_routes[0]

    screen = replay_cast(evidence / "host/watch-console.cast")
    console_routes = cast_routes(screen)
    console_route = console_routes[route["screen_ref"]]
    if console_route["channel"] != route["channel"]:
        raise ValueError("OCI channel does not match the reconstructed console")

    lead = console_route["lead"]
    relay_socket = PATCH_PANEL[lead]
    relay = rows(evidence / "host/relay_socket_legend.csv")
    operation = next(
        row["operation_name"] for row in relay if row["relay_socket"] == relay_socket
    )
    endpoint = f"{rendezvous['destination']}:{rendezvous['destination_port']}"

    report = [
        credential["label"],
        first_access["ts"],
        persistence_name,
        change_id,
        job,
        f"{operation}@{endpoint}",
        follow_on_host,
    ]

    timeline = [
        (
            credential["scheduled_utc"],
            "rotation_manifest.csv",
            f"{credential['label']} scheduled but never completed",
        ),
        (
            first_access["ts"],
            "gateway/access.log",
            f"first successful stale-token session from {first_access['src']}",
        ),
        (
            creates[0]["timestamp_utc"],
            "collaboration/audit.csv",
            f"created persistence identity {persistence_name} under {change_id}",
        ),
        (
            grants[0]["timestamp_utc"],
            "collaboration/audit.csv",
            f"added {persistence_name} to platform-admins",
        ),
        (
            job_event["timestamp_utc"],
            "collaboration/audit.csv",
            f"{persistence_name} delegated runner job {job}",
        ),
    ]
    ordered_flows = sorted(
        process_flows, key=lambda item: parse_time(item["timestamp_utc"])
    )
    for flow in ordered_flows:
        timeline.append(
            (
                flow["timestamp_utc"],
                "network/firewall.csv",
                f"{flow['action']} {flow['destination']}:{flow['destination_port']} "
                f"via {process_ref} ({flow['rule']})",
            )
        )

    disabled = [
        row
        for row in audit
        if row["action"] == "principal_disable"
        and row["target"].rsplit("/", 1)[-1]
        in {credential["principal_uuid"], persistence_uuid}
    ]
    for event in sorted(disabled, key=lambda item: parse_time(item["timestamp_utc"])):
        target_uuid = event["target"].rsplit("/", 1)[-1]
        if target_uuid == credential["principal_uuid"]:
            target_name = credential["label"]
        else:
            target_name = persistence_name
        timeline.append(
            (
                event["timestamp_utc"],
                "collaboration/audit.csv",
                f"disabled {target_name} during security review",
            )
        )

    route_chain = [
        f"runner_job={job}",
        f"process_ref={process_ref}",
        f"partner_owner={partner_record['owner']}",
        f"route_profile={profile}",
        f"oci_cache={route['cache']}",
        f"screen_ref={route['screen_ref']}",
        f"patch_lead={lead}",
        f"relay_socket={relay_socket}",
        f"operation={operation}",
        f"rendezvous={endpoint}",
        f"follow_on={follow_on_host}",
    ]

    return {
        "report": report,
        "screen": screen,
        "journal": journal,
        "routes": routes,
        "timeline": timeline,
        "route_chain": route_chain,
        "credential": credential,
        "cover": cover,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "archive",
        nargs="?",
        type=Path,
        default=Path("challenge/forensics_unrotated.zip"),
    )
    parser.add_argument("--artifacts", type=Path, help="write derived evidence files")
    parser.add_argument(
        "--submit",
        nargs="?",
        const=f"{DEFAULT_HOST}:{DEFAULT_PORT}",
        metavar="HOST[:PORT]",
        help="submit the reconstructed report to the TLS service",
    )
    parser.add_argument(
        "--allow-missing-journalctl",
        action="store_true",
        help="continue without decoding system.journal",
    )
    args = parser.parse_args()

    archive = args.archive.resolve()
    with tempfile.TemporaryDirectory(prefix="unrotated-") as temporary:
        evidence, inner_hash = unpack_handout(archive, Path(temporary))
        verified = verify_checksums(evidence)
        result = investigate(
            evidence, journal_required=not args.allow_missing_journalctl
        )
        report = result["report"]
        assert isinstance(report, list)

        print(f"[+] verified {len(verified)} evidence checksums")
        print("[+] reconstructed incident report")
        for index, answer in enumerate(report, 1):
            print(f"    report[{index}] = {answer}")

        if args.artifacts:
            write_artifacts(
                args.artifacts,
                archive,
                inner_hash,
                verified,
                result["screen"],
                result["journal"],
                result["routes"],
                result["timeline"],
                result["route_chain"],
                report,
            )
            print(f"[+] wrote analysis artifacts to {args.artifacts}")

        if args.submit:
            response = submit_report(args.submit, report)
            print(response, end="" if response.endswith("\n") else "\n")
            match = FLAG_PATTERN.search(response)
            if match is None:
                raise RuntimeError("service did not return a flag")
            print(f"[+] flag: {match.group(0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
