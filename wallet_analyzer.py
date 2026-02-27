#!/usr/bin/env python3
"""wallet.dat analyzer.

A lightweight, read-only inspection tool for Bitcoin Core style wallet files.
It does not decrypt private data and does not modify the target file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Tuple

BERKELEY_DB_MAGIC = {
    "be_0": bytes.fromhex("00053162"),
    "le_0": bytes.fromhex("62310500"),
}

SQLITE_MAGIC = b"SQLite format 3\x00"

COMMON_WALLET_MARKERS = [
    b"mkey",
    b"ckey",
    b"key",
    b"pool",
    b"name",
    b"tx",
    b"hdseed",
    b"defaultkey",
    b"purpose",
    b"version",
]


@dataclass
class WalletAnalysis:
    path: str
    size_bytes: int
    sha256: str
    entropy: float
    wallet_container_type: str
    likely_berkeley_db: bool
    berkeley_db_details: str
    marker_counts: Dict[str, int]
    wallet_marker_total: int
    printable_strings: List[str]
    preview_hex: str


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    length = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def extract_printable_strings(data: bytes, min_len: int = 4, max_items: int = 200) -> List[str]:
    strings: List[str] = []
    buf: List[int] = []

    def flush() -> None:
        nonlocal buf
        if len(buf) >= min_len:
            strings.append(bytes(buf).decode("ascii", errors="ignore"))
        buf = []

    for b in data:
        if 32 <= b <= 126:
            buf.append(b)
        else:
            flush()
            if len(strings) >= max_items:
                break
    flush()
    return strings[:max_items]


def detect_berkeley_db(data: bytes) -> Tuple[bool, str]:
    if len(data) < 16:
        return False, "File too small for Berkeley DB checks"

    hits = []
    for label, magic in BERKELEY_DB_MAGIC.items():
        if data.startswith(magic):
            hits.append(f"magic {label} at offset 0")
        if data[12:16] == magic:
            hits.append(f"magic {label} at offset 12")

    if hits:
        return True, "; ".join(hits)
    return False, "No Berkeley DB magic found at common offsets"


def detect_wallet_container(data: bytes, likely_bdb: bool) -> str:
    if data.startswith(SQLITE_MAGIC):
        return "sqlite"
    if likely_bdb:
        return "berkeley_db"
    return "unknown"


def count_markers(data: bytes) -> Dict[str, int]:
    lower = data.lower()
    return {m.decode("ascii"): lower.count(m) for m in COMMON_WALLET_MARKERS}


def hexdump_preview(data: bytes, length: int = 64) -> str:
    sample = data[:length]
    return sample.hex()


def analyze_wallet_file(path: str, max_strings: int = 200, min_string_len: int = 4) -> WalletAnalysis:
    p = Path(path)
    data = p.read_bytes()
    likely_bdb, details = detect_berkeley_db(data)
    marker_counts = count_markers(data)

    return WalletAnalysis(
        path=str(p.resolve()),
        size_bytes=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        entropy=round(shannon_entropy(data), 4),
        wallet_container_type=detect_wallet_container(data, likely_bdb),
        likely_berkeley_db=likely_bdb,
        berkeley_db_details=details,
        marker_counts=marker_counts,
        wallet_marker_total=sum(marker_counts.values()),
        printable_strings=extract_printable_strings(
            data,
            min_len=max(1, min_string_len),
            max_items=max_strings,
        ),
        preview_hex=hexdump_preview(data),
    )


def _render_human(analysis: WalletAnalysis) -> str:
    lines = [
        "wallet.dat analysis",
        "=" * 60,
        f"Path: {analysis.path}",
        f"Size: {analysis.size_bytes} bytes",
        f"SHA-256: {analysis.sha256}",
        f"Entropy: {analysis.entropy}",
        f"Container type: {analysis.wallet_container_type}",
        f"Likely Berkeley DB: {analysis.likely_berkeley_db}",
        f"Berkeley DB details: {analysis.berkeley_db_details}",
        f"Hex preview (first bytes): {analysis.preview_hex}",
        "",
        "Wallet-related marker hits:",
    ]
    for key, count in analysis.marker_counts.items():
        lines.append(f"  - {key}: {count}")
    lines.append(f"  - total markers: {analysis.wallet_marker_total}")

    lines.append("")
    lines.append("Extracted printable strings (sample):")
    if analysis.printable_strings:
        for s in analysis.printable_strings:
            lines.append(f"  - {s}")
    else:
        lines.append("  - (none)")

    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only analyzer for wallet.dat-like files",
    )
    parser.add_argument("wallet_file", help="Path to wallet.dat file")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    parser.add_argument(
        "--max-strings",
        type=int,
        default=200,
        help="Maximum number of printable strings to extract",
    )
    parser.add_argument(
        "--strings-min-len",
        type=int,
        default=4,
        help="Minimum length for extracted printable strings",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with code 2 if the file is not likely a wallet container",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not os.path.isfile(args.wallet_file):
        parser.error(f"File does not exist: {args.wallet_file}")

    analysis = analyze_wallet_file(
        args.wallet_file,
        max_strings=max(1, args.max_strings),
        min_string_len=max(1, args.strings_min_len),
    )
    if args.json:
        print(json.dumps(asdict(analysis), indent=2))
    else:
        print(_render_human(analysis))

    if args.strict and analysis.wallet_container_type == "unknown":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
