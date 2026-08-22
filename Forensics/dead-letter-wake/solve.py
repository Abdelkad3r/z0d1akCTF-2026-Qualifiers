#!/usr/bin/env python3
"""Reconstruct and decode the Dead Letter Wake authorization message."""

from __future__ import annotations

import argparse
import csv
import hashlib
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from collections import defaultdict
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFont


FLAG_PREFIX = "zdk{"
CALIBRATION_ALPHABET = "345ADEHLRT_adefkprstwz{}"
EXPECTED_FONT_SHA256 = (
    "57f73e11f51999432bf7ab22ce55b6f945d5eca1bf824404cfa9ec2e3718c84e"
)
DEFAULT_FONT_PATHS = (
    Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
    Path("/usr/local/share/fonts/DejaVuSans.ttf"),
)


@dataclass(frozen=True)
class Fragment:
    number: int
    total: int
    partial_id: str
    message_id: str
    body: bytes
    source: str
    stream: str


class Reporter:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def log(self, message: str) -> None:
        print(message, flush=True)
        self.lines.append(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_extract_zip(archive: zipfile.ZipFile, destination: Path) -> None:
    root = destination.resolve()
    for member in archive.infolist():
        target = (destination / member.filename).resolve()
        if root not in target.parents and target != root:
            raise ValueError(f"unsafe ZIP member: {member.filename}")
    archive.extractall(destination)


def safe_extract_tar(archive: tarfile.TarFile, destination: Path) -> None:
    root = destination.resolve()
    for member in archive.getmembers():
        target = (destination / member.name).resolve()
        if root not in target.parents and target != root:
            raise ValueError(f"unsafe tar member: {member.name}")
        if member.issym() or member.islnk():
            raise ValueError(f"refusing archive link: {member.name}")
    archive.extractall(destination, filter="data")


def unpack_handout(archive_path: Path, destination: Path) -> Path:
    with zipfile.ZipFile(archive_path) as archive:
        safe_extract_zip(archive, destination)

    roots = [path for path in destination.iterdir() if path.is_dir()]
    if len(roots) != 1:
        raise ValueError("expected one top-level challenge directory")
    return roots[0]


def verify_manifest(evidence_root: Path) -> list[tuple[str, str]]:
    verified: list[tuple[str, str]] = []
    manifest = evidence_root / "SHA256SUMS.txt"
    for line in manifest.read_text().splitlines():
        expected, relative = line.split(maxsplit=1)
        relative = relative.lstrip("* ")
        actual = sha256_file(evidence_root / relative)
        if actual != expected:
            raise ValueError(f"checksum mismatch for {relative}")
        verified.append((relative, actual))
    return verified


def reassemble_tcp_segments(segments: list[tuple[int, bytes]]) -> bytes:
    output = bytearray()
    next_sequence: int | None = None

    for sequence, payload in sorted(segments):
        if next_sequence is None:
            next_sequence = sequence
        segment_end = sequence + len(payload)
        if segment_end <= next_sequence:
            continue
        if sequence > next_sequence:
            raise ValueError(
                f"TCP gap: expected sequence {next_sequence}, received {sequence}"
            )
        overlap = next_sequence - sequence
        output.extend(payload[overlap:])
        next_sequence = segment_end

    return bytes(output)


def smtp_client_streams(pcap: Path) -> list[tuple[int, str, bytes]]:
    tshark = shutil.which("tshark")
    if tshark is None:
        raise RuntimeError("tshark is required to reconstruct the SMTP streams")

    command = [
        tshark,
        "-r",
        str(pcap),
        "-Y",
        "tcp.dstport == 25 && tcp.payload && !tcp.analysis.retransmission",
        "-T",
        "fields",
        "-E",
        "separator=/t",
        "-e",
        "tcp.stream",
        "-e",
        "tcp.seq",
        "-e",
        "ip.src",
        "-e",
        "tcp.payload",
    ]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    grouped: dict[tuple[int, str], list[tuple[int, bytes]]] = defaultdict(list)

    for line in result.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != 4 or not fields[3]:
            continue
        stream, sequence, source, payload = fields
        grouped[(int(stream), source)].append(
            (int(sequence), bytes.fromhex(payload.replace(":", "")))
        )

    return [
        (stream, source, reassemble_tcp_segments(segments))
        for (stream, source), segments in sorted(grouped.items())
    ]


def extract_smtp_data(client_stream: bytes) -> bytes | None:
    marker = b"DATA\r\n"
    if marker not in client_stream:
        return None
    data = client_stream.split(marker, 1)[1]
    end = data.find(b"\r\n.\r\n")
    if end < 0:
        raise ValueError("SMTP DATA command has no terminating dot line")
    return data[:end].replace(b"\r\n..", b"\r\n.")


def parse_fragment(raw_message: bytes, source: str, stream: str) -> Fragment | None:
    separator = b"\r\n\r\n"
    if separator not in raw_message:
        return None
    raw_headers, body = raw_message.split(separator, 1)
    message = BytesParser(policy=policy.default).parsebytes(raw_headers + separator)
    if message.get_content_type() != "message/partial":
        return None

    partial_id = message.get_param("id")
    number = message.get_param("number")
    total = message.get_param("total")
    if partial_id is None or number is None or total is None:
        raise ValueError("message/partial is missing id, number, or total")

    return Fragment(
        number=int(number),
        total=int(total),
        partial_id=str(partial_id),
        message_id=str(message.get("Message-ID", "")),
        body=body,
        source=source,
        stream=stream,
    )


def collect_fragments(evidence_root: Path, temporary_root: Path) -> list[Fragment]:
    queue_root = temporary_root / "mail-queue"
    queue_root.mkdir()
    with tarfile.open(evidence_root / "evidence/mail-queue.tar.gz") as archive:
        safe_extract_tar(archive, queue_root)

    queue_fragments = []
    for path in sorted(queue_root.rglob("*.eml")):
        fragment = parse_fragment(path.read_bytes(), f"queue/{path.name}", "TLS")
        if fragment is not None:
            queue_fragments.append(fragment)

    seven_part_ids = {
        fragment.partial_id for fragment in queue_fragments if fragment.total == 7
    }
    if len(seven_part_ids) != 1:
        raise ValueError("could not uniquely identify the seven-part queue series")
    target_id = seven_part_ids.pop()

    fragments = [
        fragment for fragment in queue_fragments if fragment.partial_id == target_id
    ]
    for stream, source, client_data in smtp_client_streams(
        evidence_root / "evidence/dead-letter.pcap"
    ):
        message = extract_smtp_data(client_data)
        if message is None:
            continue
        fragment = parse_fragment(
            message, f"pcap/{source}", f"tcp.stream={stream}"
        )
        if fragment is not None and fragment.partial_id == target_id:
            fragments.append(fragment)

    by_number: dict[int, Fragment] = {}
    for fragment in fragments:
        if fragment.number in by_number:
            raise ValueError(f"duplicate fragment {fragment.number}")
        by_number[fragment.number] = fragment

    expected = set(range(1, 8))
    if set(by_number) != expected:
        missing = sorted(expected - set(by_number))
        raise ValueError(f"incomplete partial series; missing {missing}")
    return [by_number[number] for number in sorted(by_number)]


def extract_pdf(reconstructed_message: bytes) -> bytes:
    message = BytesParser(policy=policy.default).parsebytes(reconstructed_message)
    attachments = [
        part
        for part in message.walk()
        if part.get_content_type() == "application/pdf"
    ]
    if len(attachments) != 1:
        raise ValueError("expected one PDF attachment")
    payload = attachments[0].get_payload(decode=True)
    if payload is None:
        raise ValueError("could not decode the PDF attachment")
    return payload


def extract_pdf_images(
    pdf_path: Path, temporary_root: Path
) -> tuple[Path, Path, str]:
    pdfimages = shutil.which("pdfimages")
    if pdfimages is None:
        raise RuntimeError("pdfimages from Poppler is required")
    prefix = temporary_root / "pdf-image"
    subprocess.run(
        [pdfimages, "-png", str(pdf_path), str(prefix)],
        check=True,
        capture_output=True,
    )
    images = sorted(temporary_root.glob("pdf-image-*.png"))
    if len(images) != 2:
        raise ValueError(f"expected two PDF raster objects, found {len(images)}")

    dimensions = {Image.open(path).size: path for path in images}
    target = dimensions.get((728, 56))
    calibration = dimensions.get((1864, 256))
    if target is None or calibration is None:
        raise ValueError(f"unexpected PDF image dimensions: {sorted(dimensions)}")

    pdftotext = shutil.which("pdftotext")
    text = ""
    if pdftotext is not None:
        result = subprocess.run(
            [pdftotext, "-layout", str(pdf_path), "-"],
            check=True,
            capture_output=True,
            text=True,
        )
        text = result.stdout
    return target, calibration, text


def de_bruijn(alphabet: str, order: int = 2) -> str:
    symbols = len(alphabet)
    workspace = [0] * (symbols * order)
    sequence: list[int] = []

    def visit(position: int, period: int) -> None:
        if position > order:
            if order % period == 0:
                sequence.extend(workspace[1 : period + 1])
            return
        workspace[position] = workspace[position - period]
        visit(position + 1, period)
        for value in range(workspace[position - period] + 1, symbols):
            workspace[position] = value
            visit(position + 1, position)

    visit(1, 1)
    cyclic = "".join(alphabet[index] for index in sequence)
    return cyclic + cyclic[0]


def shifted_rgb(gray: np.ndarray) -> np.ndarray:
    rgb = np.full((*gray.shape, 3), 255.0, dtype=np.float64)
    rgb[:, :, 1] = gray
    rgb[:, 1:, 0] = gray[:, :-1]
    rgb[:, :-1, 2] = gray[:, 1:]
    return rgb


def render_gray(text: str, size: tuple[int, int], font: ImageFont.FreeTypeFont) -> np.ndarray:
    image = Image.new("L", size, 255)
    ImageDraw.Draw(image).text((0, 2), text, font=font, fill=0)
    return np.asarray(image, dtype=np.float64)


def block_means(rgb: np.ndarray, block_size: int = 8) -> np.ndarray:
    height, width, channels = rgb.shape
    if height % block_size or width % block_size:
        raise ValueError("PIX-8 image dimensions must be divisible by eight")
    return rgb.reshape(
        height // block_size,
        block_size,
        width // block_size,
        block_size,
        channels,
    ).mean(axis=(1, 3))


def calibration_error(
    calibration_path: Path, font: ImageFont.FreeTypeFont
) -> float:
    observed = np.asarray(Image.open(calibration_path).convert("RGB"), dtype=float)
    sequence = de_bruijn(CALIBRATION_ALPHABET)
    wrapped = "\n".join(
        sequence[index : index + 90] for index in range(0, len(sequence), 90)
    )
    image = Image.new("L", (observed.shape[1], observed.shape[0]), 255)
    ImageDraw.Draw(image).multiline_text(
        (0, 2), wrapped, font=font, fill=0, spacing=4
    )
    expected = shifted_rgb(np.asarray(image, dtype=np.float64))
    return float(np.mean((expected - observed) ** 2))


def recover_flag(
    target_path: Path,
    font: ImageFont.FreeTypeFont,
    reporter: Reporter,
    beam_width: int = 16,
) -> tuple[str, float]:
    target_image = Image.open(target_path).convert("RGB")
    target = np.asarray(target_image, dtype=np.float64)
    target_blocks = block_means(target)
    width, height = target_image.size
    search_alphabet = CALIBRATION_ALPHABET.replace("{", "").replace("}", "")

    def score(text: str, complete: bool = False) -> tuple[float, float]:
        rendered = shifted_rgb(render_gray(text, (width, height), font))
        rendered_blocks = block_means(rendered)
        advance = float(font.getlength(text))
        stable_columns = target_blocks.shape[1]
        if not complete:
            # The next glyph may overhang its origin. Keeping one 8-pixel block
            # unscored prevents that future ink from penalizing a true prefix.
            stable_columns = max(1, int((advance - 8) // 8))
            stable_columns = min(stable_columns, target_blocks.shape[1])
        delta = rendered_blocks[1:5, :stable_columns] - target_blocks[
            1:5, :stable_columns
        ]
        return float(np.mean(delta * delta)), advance

    beam: list[tuple[float, str, float]] = [(0.0, FLAG_PREFIX, 0.0)]
    for _depth in range(64):
        candidates: list[tuple[float, str, float]] = []
        for _old_error, prefix, advance in beam:
            if advance > width * 0.82:
                completed = prefix + "}"
                full_error, _ = score(completed, complete=True)
                if full_error < 1.0:
                    reporter.log(
                        f"[+] Full-image PIX-8 MSE: {full_error:.6f}"
                    )
                    return completed, full_error

            for character in search_alphabet:
                candidate = prefix + character
                error, candidate_advance = score(candidate)
                if candidate_advance <= width + 32:
                    candidates.append((error, candidate, candidate_advance))

        if not candidates:
            break
        candidates.sort(key=lambda item: (item[0], item[1]))
        beam = candidates[:beam_width]
        reporter.log(
            f"[.] depth={len(beam[0][1]):02d} "
            f"best_mse={beam[0][0]:.6f} prefix={beam[0][1]}"
        )

    raise RuntimeError("beam search did not find a sub-1.0 complete rendering")


def save_visual_artifacts(
    target_path: Path,
    flag: str,
    font: ImageFont.FreeTypeFont,
    output: Path,
) -> None:
    target = Image.open(target_path).convert("RGB")
    width, height = target.size
    rendered = shifted_rgb(render_gray(flag, target.size, font))
    Image.fromarray(np.rint(rendered).astype(np.uint8), "RGB").save(
        output / "decoded-render.png"
    )

    means = np.rint(block_means(rendered)).astype(np.uint8)
    mosaic = means.repeat(8, axis=0).repeat(8, axis=1)
    Image.fromarray(mosaic, "RGB").save(output / "decoded-mosaic.png")
    target.resize((width * 2, height * 2), Image.Resampling.NEAREST).save(
        output / "target-enlarged.png"
    )


def find_font(requested: Path | None) -> Path:
    if requested is not None:
        if not requested.is_file():
            raise FileNotFoundError(requested)
        return requested
    for path in DEFAULT_FONT_PATHS:
        if path.is_file():
            return path
    raise FileNotFoundError(
        "DejaVuSans.ttf not found; pass its exact path with --font or use Docker"
    )


def write_fragment_inventory(fragments: list[Fragment], output: Path) -> None:
    with (output / "mail-fragments.csv").open("w", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(
            [
                "part",
                "total",
                "source",
                "stream",
                "message_id",
                "body_bytes",
                "body_sha256",
            ]
        )
        for fragment in fragments:
            writer.writerow(
                [
                    fragment.number,
                    fragment.total,
                    fragment.source,
                    fragment.stream,
                    fragment.message_id,
                    len(fragment.body),
                    sha256_bytes(fragment.body),
                ]
            )


def write_hash_inventory(
    archive: Path,
    verified: list[tuple[str, str]],
    output: Path,
) -> None:
    entries = [("challenge/forensics_dead-letter-wake.zip", sha256_file(archive))]
    entries.extend(verified)
    for name in (
        "reconstructed.eml",
        "recovery-authorization.pdf",
        "target.png",
        "calibration.png",
        "decoded-render.png",
        "decoded-mosaic.png",
        "target-enlarged.png",
        "mail-fragments.csv",
        "pdf-text.txt",
        "solver-output.txt",
    ):
        path = output / name
        if path.exists():
            entries.append((f"artifacts/{name}", sha256_file(path)))
    (output / "evidence-hashes.txt").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in entries)
    )


def solve(archive: Path, output: Path, font_path: Path) -> str:
    reporter = Reporter()
    archive = archive.resolve()
    output.mkdir(parents=True, exist_ok=True)

    reporter.log(f"[+] Handout SHA-256: {sha256_file(archive)}")
    with tempfile.TemporaryDirectory(prefix="dead-letter-wake-") as temporary:
        temporary_root = Path(temporary)
        evidence_root = unpack_handout(archive, temporary_root / "handout")
        verified = verify_manifest(evidence_root)
        for relative, digest in verified:
            reporter.log(f"[+] Verified {relative}: {digest}")

        fragments = collect_fragments(evidence_root, temporary_root)
        reporter.log(f"[+] Partial MIME identity: {fragments[0].partial_id}")
        for fragment in fragments:
            reporter.log(
                f"[+] Part {fragment.number}/7: {fragment.source} "
                f"{fragment.stream} ({len(fragment.body)} raw bytes)"
            )
        write_fragment_inventory(fragments, output)

        reconstructed = b"".join(fragment.body for fragment in fragments)
        reconstructed_path = output / "reconstructed.eml"
        reconstructed_path.write_bytes(reconstructed)
        reporter.log(
            f"[+] Reconstructed MIME SHA-256: {sha256_bytes(reconstructed)}"
        )

        pdf = extract_pdf(reconstructed)
        pdf_path = output / "recovery-authorization.pdf"
        pdf_path.write_bytes(pdf)
        reporter.log(f"[+] Extracted PDF SHA-256: {sha256_bytes(pdf)}")

        target_source, calibration_source, pdf_text = extract_pdf_images(
            pdf_path, temporary_root
        )
        target_path = output / "target.png"
        calibration_path = output / "calibration.png"
        shutil.copyfile(target_source, target_path)
        shutil.copyfile(calibration_source, calibration_path)
        if pdf_text:
            (output / "pdf-text.txt").write_text(pdf_text)
        reporter.log(
            f"[+] Target raster: 728x56, SHA-256 {sha256_file(target_path)}"
        )
        reporter.log(
            "[+] Calibration raster: 1864x256, SHA-256 "
            f"{sha256_file(calibration_path)}"
        )

        font_digest = sha256_file(font_path)
        reporter.log(f"[+] Renderer font SHA-256: {font_digest}")
        if font_digest != EXPECTED_FONT_SHA256:
            reporter.log("[!] Font hash differs from the calibrated DejaVu Sans file")
        font = ImageFont.truetype(str(font_path), 32)
        error = calibration_error(calibration_path, font)
        reporter.log(f"[+] Calibration full-image MSE: {error:.6f}")
        if error >= 2.0:
            raise ValueError("selected renderer does not match the calibration image")

        flag, _flag_error = recover_flag(target_path, font, reporter)
        if re.fullmatch(r"zdk\{[^}\r\n]+\}", flag) is None:
            raise ValueError(f"decoded value is not a flag: {flag}")
        save_visual_artifacts(target_path, flag, font, output)
        reporter.log(f"[+] FLAG: {flag}")

        (output / "solver-output.txt").write_text("\n".join(reporter.lines) + "\n")
        write_hash_inventory(archive, verified, output)
        return flag


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help="original challenge ZIP")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts"),
        help="derived artifact directory (default: artifacts)",
    )
    parser.add_argument(
        "--font",
        type=Path,
        help="path to the calibrated DejaVuSans.ttf",
    )
    arguments = parser.parse_args()
    solve(arguments.archive, arguments.output, find_font(arguments.font))


if __name__ == "__main__":
    main()
