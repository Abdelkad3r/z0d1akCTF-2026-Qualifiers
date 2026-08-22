import os
import json
import socketserver
import hashlib
from ecdsa import SECP256k1
from ecdsa.ellipticcurve import INFINITY

G = SECP256k1.generator
N = SECP256k1.order                      # 256-bit prime group order
NBITS = N.bit_length()                   # == 256

PITCH_BITS = 10
SUFFIX_BITS = NBITS - PITCH_BITS
SUFFIX_BOUND = 1 << SUFFIX_BITS
SONG_ID = os.urandom(8).hex()

PRIV_MSG = "unlock:release-the-tide"

D = int.from_bytes(os.urandom(32), "big") % (N - 1) + 1
Q = D * G                                # public key point

FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")


def rng_below(bound):
    nbytes = (bound.bit_length() + 7) // 8
    while True:
        v = int.from_bytes(os.urandom(nbytes), "big") % bound
        if v >= 1:
            return v


def msg_hash(msg):
    h = int.from_bytes(hashlib.sha256(msg.encode()).digest(), "big")
    return h % N


def public_pitch(msg):
    material = (SONG_ID + ":" + msg).encode()
    h = int.from_bytes(hashlib.sha256(material).digest(), "big")
    return h >> (256 - PITCH_BITS)


def shaped_nonce(msg):
    prefix = public_pitch(msg) << SUFFIX_BITS
    while True:
        k = prefix | (rng_below(SUFFIX_BOUND) - 1)
        if 1 <= k < N:
            return k


def sign(msg):
    z = msg_hash(msg)
    while True:
        k = shaped_nonce(msg)
        R = k * G
        r = R.x() % N
        if r == 0:
            continue
        s = (pow(k, -1, N) * (z + r * D)) % N
        if s == 0:
            continue
        return r, s


def verify(msg, r, s):
    if not (1 <= r < N and 1 <= s < N):
        return False
    z = msg_hash(msg)
    w = pow(s, -1, N)
    u1 = (z * w) % N
    u2 = (r * w) % N
    P = u1 * G + u2 * Q
    if P == INFINITY:
        return False
    return (P.x() % N) == r


def read_flag():
    try:
        with open(FLAG_PATH) as f:
            return f.read().strip()
    except OSError:
        return "zdk{flag_file_missing_on_server}"


class Handler(socketserver.StreamRequestHandler):
    timeout = 120

    def _send(self, obj):
        self.wfile.write((json.dumps(obj) + "\n").encode())
        self.wfile.flush()

    def handle(self):
        self._send({
            "banner": "The Siren hums on the rocks. Send her a line to sign.",
            "hint": "cmds: pubkey | sign{msg} | unlock{r,s}",
        })
        for raw in self.rfile:
            raw = raw.strip()
            if not raw:
                continue
            try:
                req = json.loads(raw.decode())
            except Exception:
                self._send({"error": "malformed json"})
                continue
            cmd = req.get("cmd")
            try:
                if cmd == "pubkey":
                    self._send({
                        "curve": "secp256k1",
                        "Qx": hex(Q.x()),
                        "Qy": hex(Q.y()),
                        "n": hex(N),
                        "song_id": SONG_ID,
                        "pitch_bits": PITCH_BITS,
                        "priv_msg": PRIV_MSG,
                    })
                elif cmd == "sign":
                    msg = req.get("msg", "")
                    if not isinstance(msg, str):
                        self._send({"error": "msg must be a string"})
                        continue
                    if msg == PRIV_MSG:
                        self._send({"error": "the Siren will not sing that word"})
                        continue
                    r, s = sign(msg)
                    self._send({"r": hex(r), "s": hex(s)})
                elif cmd == "unlock":
                    try:
                        r = int(req.get("r"), 16)
                        s = int(req.get("s"), 16)
                    except Exception:
                        self._send({"error": "r,s must be hex strings"})
                        continue
                    if verify(PRIV_MSG, r, s):
                        self._send({"flag": read_flag()})
                    else:
                        self._send({"error": "that is not the Siren's hand"})
                else:
                    self._send({"error": "unknown cmd"})
            except Exception as e:
                self._send({"error": "server error: %s" % e})


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "1337"))
    srv = Server((host, port), Handler)
    print("siren listening on %s:%d" % (host, port))
    srv.serve_forever()


if __name__ == "__main__":
    main()
