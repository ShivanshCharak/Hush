"""Load an event stream and its pipeline trace into a local DuckDB file."""
from __future__ import annotations

import json
import argparse
import threading
import time
from pathlib import Path
from typing import Iterable

import duckdb


def read_jsonl(path: Path) -> Iterable[dict]:
    with path.open(encoding="utf-8") as source:
        for line in source:
            if line.strip():
                yield json.loads(line)


def severity(event: dict) -> str:
    status = int(event.get("status") or 0)
    result = str(event.get("result", "")).casefold()
    if status >= 500:
        return "error"
    if status >= 400 or result in {"failure", "failed", "denied", "auth_failure"}:
        return "warning"
    return "info"


def ingest(events_path: Path, trace_path: Path, database_path: Path) -> dict:
    database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = duckdb.connect(str(database_path))
    try:
        connection.execute("DROP TABLE IF EXISTS alerts")
        connection.execute("DROP TABLE IF EXISTS windows")
        connection.execute("DROP TABLE IF EXISTS events")
        connection.execute("CREATE TABLE events(event_id BIGINT PRIMARY KEY, timestamp VARCHAR, severity VARCHAR, src_ip VARCHAR, method VARCHAR, path VARCHAR, status INTEGER, username VARCHAR, user_agent VARCHAR, session_id VARCHAR, raw_json VARCHAR)")
        event_rows = []
        for event in read_jsonl(events_path):
            event_rows.append((int(event["event_id"]), event.get("timestamp", ""), severity(event), event.get("src_ip"),
                               event.get("method"), event.get("path"), event.get("status"), event.get("username"),
                               event.get("user_agent"), event.get("session_id"), json.dumps(event, ensure_ascii=False)))
        connection.executemany("INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", event_rows)
        connection.execute("CREATE TABLE windows(event_start BIGINT, event_end BIGINT, speak BOOLEAN, kind VARCHAR, confidence DOUBLE, evidence_ids VARCHAR, gate_emit BOOLEAN, gate_reason VARCHAR, alert_id VARCHAR, explanation VARCHAR, trace_json VARCHAR, UNIQUE(event_start,event_end))")
        windows = list(read_jsonl(trace_path))
        connection.executemany("INSERT INTO windows VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", [
            (int(row["event_start"]), int(row["event_end"]), bool(row.get("speak")), row.get("kind", "none"),
             row.get("confidence"), json.dumps(row.get("evidence_ids", [])), bool(row.get("gate_emit")),
             row.get("gate_reason", ""), row.get("alert_id"), json.dumps(row.get("explanation"), ensure_ascii=False),
             json.dumps(row, ensure_ascii=False)) for row in windows])
        connection.execute("CREATE TABLE alerts AS SELECT alert_id, event_start, event_end, kind, confidence, evidence_ids, gate_reason, explanation FROM windows WHERE gate_emit")
        return {"events": len(event_rows), "windows": len(windows), "alerts": sum(bool(row.get("gate_emit")) for row in windows)}
    finally:
        connection.close()


def _watch_records(events_path: Path, trace_path: Path, database_path: Path, interval: float, stop: threading.Event) -> None:
    offsets = {events_path: events_path.stat().st_size if events_path.exists() else 0,
               trace_path: trace_path.stat().st_size if trace_path.exists() else 0}
    buffers = {events_path: b"", trace_path: b""}
    while not stop.is_set():
        new_events, new_traces = [], []
        for path, target in ((events_path, new_events), (trace_path, new_traces)):
            if not path.exists():
                continue
            with path.open("rb") as source:
                source.seek(offsets[path])
                chunk = source.read()
                offsets[path] += len(chunk)
            combined = buffers[path] + chunk
            lines = combined.split(b"\n")
            buffers[path] = lines.pop()
            for line in lines:
                if line.strip():
                    try:
                        target.append(json.loads(line))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        continue
        if new_events or new_traces:
            connection = duckdb.connect(str(database_path))
            try:
                if new_events:
                    connection.executemany("INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING", [
                        (int(event["event_id"]), event.get("timestamp", ""), severity(event), event.get("src_ip"), event.get("method"),
                         event.get("path"), event.get("status"), event.get("username"), event.get("user_agent"),
                         event.get("session_id"), json.dumps(event, ensure_ascii=False)) for event in new_events])
                for row in new_traces:
                    values = (int(row["event_start"]), int(row["event_end"]), bool(row.get("speak")), row.get("kind", "none"),
                              row.get("confidence"), json.dumps(row.get("evidence_ids", [])), bool(row.get("gate_emit")),
                              row.get("gate_reason", ""), row.get("alert_id"), json.dumps(row.get("explanation"), ensure_ascii=False),
                              json.dumps(row, ensure_ascii=False))
                    connection.execute("INSERT INTO windows VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(event_start,event_end) DO NOTHING", values)
                    if row.get("gate_emit"):
                        connection.execute("INSERT INTO alerts SELECT ?,?,?,?,?,?,?,? WHERE NOT EXISTS (SELECT 1 FROM alerts WHERE alert_id=?)",
                                           (row.get("alert_id"), int(row["event_start"]), int(row["event_end"]), row.get("kind"), row.get("confidence"),
                                            json.dumps(row.get("evidence_ids", [])), row.get("gate_reason", ""), json.dumps(row.get("explanation"), ensure_ascii=False), row.get("alert_id")))
            finally:
                connection.close()
        stop.wait(interval)


def start_watcher(events_path: Path, trace_path: Path, database_path: Path, interval: float = 0.5) -> threading.Thread:
    if not database_path.exists():
        ingest(events_path, trace_path, database_path)
    stop = threading.Event()
    thread = threading.Thread(target=_watch_records, args=(events_path, trace_path, database_path, interval, stop), daemon=True)
    thread.start()
    return thread


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", type=Path)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--database", type=Path, default=root / "dashboard/data/dashboard.duckdb")
    args = parser.parse_args()
    print(json.dumps(ingest(args.events, args.trace, args.database)))
