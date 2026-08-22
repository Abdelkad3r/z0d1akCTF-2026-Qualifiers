#!/usr/bin/env python3
"""
z0d1akCTF 2026 Qualifiers - layer-eight (Forensics, 120 pts)

The handout `app-image.tar` is an OCI/Docker image (`nimbusnotes:1.4.2`). A build
`deploy_key` and a `provenance.py` are added in early layers and `rm`-ed in a
later layer - but a container "deletion" is only a whiteout marker (`.wh.*`); the
real bytes survive in the earlier layer's tar. We carve them back, then follow
`provenance.py` to decrypt an AES-256-GCM envelope that was sharded across the
image's provenance labels.

Dependency-free: uses the bundled pure-python `aesgcm` (no pip needed).

    python3 solve.py [app-image.tar]
"""
import sys, os, io, json, gzip, tarfile, base64, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aesgcm import gcm_decrypt

TAR = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "challenge", "app-image.tar")


def load_oci(path):
    """Return (blobs: digest->bytes, index, manifest, config)."""
    blobs = {}
    with tarfile.open(path) as t:
        members = {m.name: m for m in t.getmembers() if m.isfile()}
        for name, m in members.items():
            if name.startswith("blobs/sha256/"):
                blobs["sha256:" + name.split("/")[-1]] = t.extractfile(m).read()
        index = json.loads(t.extractfile(members["index.json"]).read())
    man_digest = index["manifests"][0]["digest"]
    manifest = json.loads(blobs[man_digest])
    config = json.loads(blobs[manifest["config"]["digest"]])
    return blobs, index, manifest, config


def carve_layers(blobs, manifest):
    """Walk layers in order; return (added_files, whiteouts_per_layer)."""
    added = {}                 # path -> (layer_idx, bytes)
    whiteouts = {}             # layer_idx -> [paths]
    for idx, layer in enumerate(manifest["layers"], start=1):
        raw = gzip.decompress(blobs[layer["digest"]])
        with tarfile.open(fileobj=io.BytesIO(raw)) as lt:
            for m in lt.getmembers():
                base = os.path.basename(m.name)
                if base.startswith(".wh."):
                    real = m.name.replace(".wh.", "")
                    whiteouts.setdefault(idx, []).append(real)
                elif m.isfile():
                    added[m.name] = (idx, lt.extractfile(m).read())
    return added, whiteouts


def main():
    blobs, index, manifest, config = load_oci(TAR)
    print(f"[*] image: {index['manifests'][0]['annotations'].get('io.containerd.image.name')}")
    added, whiteouts = carve_layers(blobs, manifest)

    # The whiteout layer (challenge name: "layer-eight")
    for idx, paths in sorted(whiteouts.items()):
        print(f"[*] layer {idx} whiteouts (deleted files): {paths}")

    # Carve the "deleted" secret + the reassembly script from earlier layers
    deploy_key = added["app/.secrets/deploy_key"][1]
    prov_layer, _ = added["usr/lib/nimbus/provenance.py"]
    print(f"[*] recovered deploy_key ({len(deploy_key)} bytes) from layer "
          f"{added['app/.secrets/deploy_key'][0]}")
    print(f"[*] recovered provenance.py from layer {prov_layer}")

    # Provenance labels
    L = config["config"]["Labels"]
    parts = {"a": L["com.nimbusnotes.provenance.part-a"],
             "b": L["com.nimbusnotes.provenance.part-b"],
             "c": L["com.nimbusnotes.provenance.part-c"]}
    layout = L["com.nimbusnotes.provenance.layout"].split(",")  # e.g. ["c","a","b"]
    step = L["com.nimbusnotes.provenance.step"]
    print(f"[*] layout={layout} step={step}")

    # Reassemble base64(envelope) in layout order, then decode
    envelope = base64.b64decode("".join(parts[k] for k in layout))
    version, nonce, tag, ct = envelope[0], envelope[1:13], envelope[-16:], envelope[13:-16]
    assert version == 1 and len(nonce) == 12, "unexpected envelope framing"
    print(f"[*] envelope: version={version} nonce={nonce!r} ct={len(ct)}B tag={tag.hex()}")

    # Key + AAD exactly as provenance.py computes them
    key = hashlib.sha256(deploy_key + bytes.fromhex(step.split(":", 1)[1])).digest()
    aad = ("nimbusnotes:" + config["config"]["Labels"]["org.opencontainers.image.version"]
           + "|" + step).encode()
    pt, ok = gcm_decrypt(key, nonce, ct, tag, aad)
    print(f"[*] GCM tag verified: {ok}")
    if ok:
        print(f"[+] FLAG: {pt.decode()}")
        return 0
    print("[-] tag mismatch")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
