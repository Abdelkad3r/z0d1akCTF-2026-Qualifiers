#!/bin/sh
set -eu
test -r /app/.secrets/deploy_key
python3 /usr/lib/nimbus/provenance.py
