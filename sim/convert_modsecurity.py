#!/usr/bin/env python3
"""Convert the Zenodo ModSecurity audit logs to Decider-Sec web events."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import re
import zipfile
from datetime import datetime
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARCHIVE = ROOT / "sim/capture/external/modsecurity-zenodo-17178461/owasp.zip"
DEFAULT_RAW = ROOT / "sim/capture/external/modsecurity-zenodo-17178461/raw"
DEFAULT_OUTPUT = ROOT / "data/external/modsecurity_events.jsonl"
SOURCE_ID = "zenodo:17178461"
SOURCE_PAPER_REPORTED_REQUESTS = 147_205

START_RE = re.compile(r"(?m)^--([0-9A-Fa-f]+)-A--\r?\n")
SECTION_RE = re.compile(r"(?m)^--[0-9A-Fa-f]+-([A-Z])--\r?\n")
FIELD_RE = re.compile(r'\[(id|msg|severity|tag|data)\s+"((?:\\.|[^"\\])*)"\]')
HEADER_RE = re.compile(r"^([^:\s][^:]*):\s*(.*)$")
REQUEST_RE = re.compile(r"^(\S+)\s+(\S+)\s+HTTP/\d(?:\.\d)?$")
RESPONSE_RE = re.compile(r"^HTTP/\d(?:\.\d)?\s+(\d{3})(?:\s|$)")
TIMESTAMP_RE = re.compile(r"^\[([^]]+)\]\s+(\S+)(?:\s+(.*))?$")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def extract_archive(archive: Path, raw_dir: Path) -> list[Path]:
    raw_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as bundle:
        for info in bundle.infolist():
            member = PurePosixPath(info.filename)
            if member.is_absolute() or ".." in member.parts:
                raise ValueError(f"Unsafe archive member: {info.filename}")
            destination = raw_dir.joinpath(*member.parts)
            if info.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            if not destination.exists() or destination.stat().st_size != info.file_size:
                with bundle.open(info) as source, destination.open("wb") as target:
                    while block := source.read(1024 * 1024):
                        target.write(block)
    return sorted(raw_dir.glob("*/modsec_audit.anon.log"), key=lambda p: datetime.strptime(p.parent.name, "%d-%b-%Y"))


def split_records(text: str):
    starts = list(START_RE.finditer(text))
    for index, match in enumerate(starts):
        end = text.find(f"--{match.group(1)}-Z--", match.end())
        if end < 0:
            yield match.group(1), text[match.end():], "missing_record_terminator"
            continue
        next_start = starts[index + 1].start() if index + 1 < len(starts) else len(text)
        if end >= next_start:
            yield match.group(1), text[match.end():next_start], "missing_record_terminator"
            continue
        yield match.group(1), text[match.end():end], None


def parse_sections(chunk: str) -> dict[str, str]:
    matches = list(SECTION_RE.finditer(chunk))
    sections: dict[str, str] = {}
    if matches:
        sections["A"] = chunk[:matches[0].start()].strip("\r\n")
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(chunk)
        sections[match.group(1)] = chunk[match.end():end].strip("\r\n")
    return sections


def parse_headers(lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    last_key: str | None = None
    for line in lines:
        if not line:
            continue
        if line[:1].isspace() and last_key:
            headers[last_key] += " " + line.strip()
            continue
        match = HEADER_RE.match(line)
        if match:
            last_key = match.group(1).strip().lower()
            headers[last_key] = match.group(2).strip()
    return headers


def parse_rules(section: str) -> list[dict[str, object]]:
    rules = []
    for line in section.splitlines():
        if not line.startswith("Message:"):
            continue
        fields: dict[str, list[str]] = {}
        for key, value in FIELD_RE.findall(line):
            fields.setdefault(key, []).append(value.replace('\\"', '"').replace("\\\\", "\\"))
        if fields:
            rules.append(
                {
                    "id": fields.get("id", [None])[0],
                    "message": fields.get("msg", [None])[0],
                    "severity": fields.get("severity", [None])[0],
                    "tags": fields.get("tag", []),
                    "matched_data": fields.get("data", []),
                }
            )
    return rules


def parse_event(audit_id: str, chunk: str, session_id: str, event_id: int) -> dict[str, object]:
    sections = parse_sections(chunk)
    header_lines = sections.get("A", "").splitlines()
    if not header_lines:
        raise ValueError("missing_header_section")
    header_match = TIMESTAMP_RE.match(header_lines[0])
    if not header_match:
        raise ValueError("invalid_header_line")
    timestamp = datetime.strptime(header_match.group(1), "%d/%b/%Y:%H:%M:%S %z").isoformat()
    meta = (header_match.group(3) or "").split()
    if len(meta) < 4:
        raise ValueError("missing_client_or_server_address")
    src_ip = meta[0]
    source_unique_id = header_match.group(2)

    request_lines = sections.get("B", "").splitlines()
    if not request_lines:
        raise ValueError("missing_request_section")
    request_match = REQUEST_RE.match(request_lines[0].strip())
    if not request_match:
        raise ValueError("invalid_request_line")
    method, target = request_match.group(1), request_match.group(2)
    parsed_target = urlsplit(target)
    path = parsed_target.path or "/"
    query = parsed_target.query
    request_headers = parse_headers(request_lines[1:])

    response_lines = sections.get("F", "").splitlines()
    response_match = RESPONSE_RE.match(response_lines[0].strip()) if response_lines else None
    response_headers = parse_headers(response_lines[1:]) if response_lines else {}
    content_length = response_headers.get("content-length")
    try:
        response_bytes = int(content_length) if content_length is not None else None
    except ValueError:
        response_bytes = None

    producer_match = re.search(r"(?m)^Producer:\s*(.+)$", chunk)
    return {
        "event_id": event_id,
        "session_id": session_id,
        "timestamp": timestamp,
        "src_ip": src_ip,
        "method": method,
        "path": path,
        "query": query,
        "status": int(response_match.group(1)) if response_match else None,
        "bytes": response_bytes,
        "user_agent": request_headers.get("user-agent"),
        "referer": request_headers.get("referer"),
        "source_dataset": SOURCE_ID,
        "source_record_marker_id": audit_id,
        "source_unique_id": source_unique_id,
        "waf_flagged": True,
        "modsecurity": {
            "rules": parse_rules(sections.get("H", "")),
            "producer": producer_match.group(1).strip() if producer_match else None,
            "engine_mode": (re.search(r'(?m)^Engine-Mode:\s*"?([^"\r\n]+)', chunk) or [None, None])[1],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, default=DEFAULT_ARCHIVE)
    parser.add_argument("--raw-dir", type=Path, default=DEFAULT_RAW)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    raw_files = extract_archive(args.archive, args.raw_dir)
    if not raw_files:
        raise SystemExit(f"No daily audit logs found under {args.raw_dir}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    errors_path = args.output.with_suffix(".errors.jsonl")
    manifest_path = args.output.with_suffix(".manifest.json")
    output_tmp = args.output.with_suffix(args.output.suffix + ".tmp")
    errors_tmp = errors_path.with_suffix(errors_path.suffix + ".tmp")
    input_counts: dict[str, dict[str, int]] = {}
    total_records = 0
    converted = 0
    failures = 0
    next_event_id = 0
    marker_id_counts: Counter[str] = Counter()
    transaction_id_counts: Counter[str] = Counter()

    with output_tmp.open("w", encoding="utf-8", newline="\n") as output, errors_tmp.open("w", encoding="utf-8", newline="\n") as errors:
        for raw_file in raw_files:
            session_id = raw_file.parent.name
            day_records = day_converted = 0
            text = raw_file.read_text(encoding="utf-8", errors="replace")
            for audit_id, chunk, record_error in split_records(text):
                day_records += 1
                total_records += 1
                try:
                    if record_error:
                        raise ValueError(record_error)
                    event = parse_event(audit_id, chunk, session_id, next_event_id)
                except (ValueError, OverflowError) as exc:
                    errors.write(json.dumps({"session_id": session_id, "source_record_marker_id": audit_id, "error": str(exc)}, ensure_ascii=False) + "\n")
                    failures += 1
                    continue
                output.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
                marker_id_counts[audit_id] += 1
                transaction_id_counts[str(event["source_unique_id"])] += 1
                next_event_id += 1
                converted += 1
                day_converted += 1
            input_counts[session_id] = {"records_seen": day_records, "events_written": day_converted}

    output_tmp.replace(args.output)
    errors_tmp.replace(errors_path)
    manifest = {
        "source_dataset": SOURCE_ID,
        "source_record_url": "https://zenodo.org/records/17178461",
        "source_paper_doi": "10.3390/data10110186",
        "archive_path": str(args.archive.relative_to(ROOT)) if args.archive.is_relative_to(ROOT) else str(args.archive),
        "archive_sha256": sha256_file(args.archive),
        "source_files": len(raw_files),
        "records_seen": total_records,
        "events_written": converted,
        "source_paper_reported_requests": SOURCE_PAPER_REPORTED_REQUESTS,
        "record_count_difference_from_paper": total_records - SOURCE_PAPER_REPORTED_REQUESTS,
        "count_reconciliation": {
            "status": "source_paper_mismatch_unresolved",
            "archive_count_used": total_records,
            "transaction_ids_are_unique": len(transaction_id_counts) == converted,
            "policy": "Keep every parseable archive transaction; do not discard records to force agreement with the paper total.",
        },
        "parse_failures": failures,
        "unique_record_marker_ids": len(marker_id_counts),
        "duplicate_record_marker_ids": sum(count > 1 for count in marker_id_counts.values()),
        "rows_with_duplicate_record_marker_ids": sum(count - 1 for count in marker_id_counts.values()),
        "unique_modsecurity_transaction_ids": len(transaction_id_counts),
        "duplicate_modsecurity_transaction_ids": sum(count > 1 for count in transaction_id_counts.values()),
        "rows_with_duplicate_modsecurity_transaction_ids": sum(count - 1 for count in transaction_id_counts.values()),
        "output_path": str(args.output.relative_to(ROOT)) if args.output.is_relative_to(ROOT) else str(args.output),
        "output_sha256": sha256_file(args.output),
        "errors_path": str(errors_path.relative_to(ROOT)) if errors_path.is_relative_to(ROOT) else str(errors_path),
        "counts_by_session": input_counts,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"events_written": converted, "records_seen": total_records, "parse_failures": failures, "output": str(args.output), "manifest": str(manifest_path)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
