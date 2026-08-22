#!/usr/bin/env python3
import base64, hashlib, os
from Crypto.Cipher import AES
key_bytes = open('/app/.secrets/deploy_key','rb').read()
step = os.environ['NIMBUS_STEP_DIGEST']
k = hashlib.sha256(key_bytes + bytes.fromhex(step.split(':',1)[1])).digest()
aad = ('nimbusnotes:1.4.2|' + step).encode()
# envelope v1: version || nonce[12] || ciphertext || tag[16]
# the registry adapter shards base64(envelope) across provenance labels
