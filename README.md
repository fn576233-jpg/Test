# wallet.dat Analyzer

A small **read-only** CLI utility for inspecting `wallet.dat`-style files.

## Features

- Calculates SHA-256 and file size.
- Estimates Shannon entropy (quick randomness signal).
- Detects common wallet container formats (`Berkeley DB` and `SQLite`).
- Counts common wallet-related markers (`mkey`, `ckey`, `pool`, etc.).
- Extracts printable strings for triage.
- Optional strict mode for automation (`--strict` exits non-zero when file doesn't look wallet-like).

## Usage

```bash
python3 wallet_analyzer.py /path/to/wallet.dat
```

JSON output:

```bash
python3 wallet_analyzer.py /path/to/wallet.dat --json
```

Tune string extraction:

```bash
python3 wallet_analyzer.py /path/to/wallet.dat --max-strings 50 --strings-min-len 6
```

Strict mode (CI / scripted triage):

```bash
python3 wallet_analyzer.py /path/to/file --strict
```

## Notes

- This tool **does not** decrypt wallet contents.
- This tool **does not** perform password cracking or padding-oracle attacks.
- This tool **does not** modify files.
- It is intended for forensic triage and diagnostics.
