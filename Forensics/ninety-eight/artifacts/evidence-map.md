# 99.8% — evidence map & decoys

The handout (`forensics_ninety_eight.zip`) unpacks to an `evidence/` tree modelling
an interrupted qBittorrent download of `ubuntu_docs_backup_2025.iso`.

## Decoy flags (all of these are fake — note the tells)

| File | Planted token | Tell |
| --- | --- | --- |
| `fragments/crc_report.txt` | `zdk{pH4K3_crc_fix}` | **pH4K3** = "fake"; report even says "stale temporary offsets" |
| `fragments/media_index.tmp` | `zdk{pH4K3_crc_fix}` | same fake token |
| `memory/carved_strings.txt` | `zdk{d3c0Y_malf_toc}` | **d3c0Y** = "decoy" |
| `session/qBittorrent-data.ini` | `zdk{d3c0Y_tracker_noise}` | **d3c0Y** = "decoy" |
| `session/logs/qbittorrent.log` | `zdk{d3c0Y_tracker_noise}` | **d3c0Y** = "decoy" |

The challenge blurb ("idk why my claude couldn't help") is a taunt: an assistant
that greps for `zdk{` and stops will hand back one of these.

## Signal — the real scheme

| File | Contribution |
| --- | --- |
| `memory/carved_strings.txt` | `qbcn_kdf = sha256(domain \|\| piece_window \|\| piece_length_word)` |
| `fragments/media_index.tmp` | `qbcn_piece_window = pieces[0:16]` (→ first 16 piece hashes), `piece_length_word = uint32le` |
| `session/logs/disk_io.log` | `keycheck = sha256(key)[0:8]`, `stream_block[n] = sha256(key \|\| uint32le(n))` |
| `memory/qbcore_2025_11_18.mem` | tail KDF trace: `domain_ascii=ninety-eight/qbcn/v1`, `domain_terminator=00`; also `qbt_piece_hash_hint=58ff…6435` (= piece 5) |
| `session/BT_backup/….torrent` | `piece length = 131072`, the 16 SHA-1 `pieces`, `length = 2098228` |
| `session/BT_backup/….fastresume` | `unfinished` = piece 5, `bitmask=ffff0000`; confirms which piece stalled |
| `fragments/download.tmp.!qB` | the partfile; its **final partial piece (index 16)** is the `HREG` container holding the encrypted flag |

## Misdirection to notice

* The `.torrent` `pieces` field is declared `340:` but only **339** bytes are
  present — the last SHA-1 is truncated by one byte (`malf_toc`). It doesn't
  matter: only `pieces[0:320]` (the first 16 hashes) feed the KDF.
* The `qbt_piece_hash_hint` / fastresume point at **piece 5** as "the missing
  0.2%", but the flag container lives in the **final** piece (16). Piece 5 is a
  red herring for the key material, not the flag location.

## Result

```
key      = sha256(b"ninety-eight/qbcn/v1\x00" + pieces[0:320] + uint32le(131072))
         = d2515578cf57736215ed384a7f75ee07e34fc38378be4fd454c9d52cffa40e68
keycheck = 32de14e7f9606b68              # equals the value stored in the HREG header

HREG(final piece) -> ciphertext XOR sha256(key||uint32le(n)) -> QBCN record:
  b'QBCN\x01\x00\x15\x00zdk{Q8IT_hI6H_g0a7ED}...'

FLAG = zdk{Q8IT_hI6H_g0a7ED}
```
