"""FastAPI read API for the local DuckDB log explorer."""
from __future__ import annotations

import json
import os
import time
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import duckdb
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import StreamingResponse
from dashboard.api.ingest import start_watcher

ROOT = Path(__file__).resolve().parents[2]
DB_PATH = Path(os.environ.get("HUSH_DASHBOARD_DB", ROOT / "dashboard/data/dashboard.duckdb"))
app = FastAPI(title="Decider-Sec Log Explorer")
_watch_thread: threading.Thread | None = None


@app.on_event("startup")
def enable_file_tail() -> None:
    global _watch_thread
    events_path = os.environ.get("HUSH_EVENTS_PATH")
    trace_path = os.environ.get("HUSH_TRACE_PATH")
    if events_path and trace_path and Path(events_path).exists() and Path(trace_path).exists():
        _watch_thread = start_watcher(Path(events_path), Path(trace_path), DB_PATH)


def _filters(filters: list[str]) -> tuple[str, list[str]]:
    clauses, values = [], []
    allowed = {"severity", "src_ip", "kind", "path", "alert_id", "status", "method", "username", "user_agent"}
    for item in filters:
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        if key not in allowed or not value:
            continue
        if key == "kind":
            clauses.append("EXISTS (SELECT 1 FROM windows w WHERE w.event_start <= e.event_id AND w.event_end >= e.event_id AND w.kind = ?)")
        elif key == "alert_id":
            clauses.append("EXISTS (SELECT 1 FROM alerts a WHERE a.event_start <= e.event_id AND a.event_end >= e.event_id AND a.alert_id = ?)")
        elif key == "path":
            clauses.append("e.path ILIKE ?")
            value = f"%{value}%"
        else:
            clauses.append(f"e.{key} = ?")
        values.append(value)
    return (" AND ".join(clauses) if clauses else "TRUE", values)


def _range(from_: str | None, to: str | None) -> tuple[str, list[str]]:
    clauses, args = [], []
    if from_:
        clauses.append("try_cast(e.timestamp AS TIMESTAMPTZ) >= try_cast(? AS TIMESTAMPTZ)")
        args.append(from_)
    if to:
        clauses.append("try_cast(e.timestamp AS TIMESTAMPTZ) <= try_cast(? AS TIMESTAMPTZ)")
        args.append(to)
    return (" AND ".join(clauses) if clauses else "TRUE", args)


def _connection():
    if not DB_PATH.exists():
        raise HTTPException(503, "Dashboard data is not loaded; run dashboard/api/ingest.py first.")
    return duckdb.connect(str(DB_PATH))


def _event(row: tuple) -> dict[str, Any]:
    return {"event_id": row[0], "timestamp": row[1], "severity": row[2], "src_ip": row[3], "method": row[4],
            "path": row[5], "status": row[6], "username": row[7], "user_agent": row[8], "session_id": row[9],
            "raw": json.loads(row[10]), "verdict": json.loads(row[11]) if row[11] else None}


@app.get("/")
def index():
    return {"service": "Decider-Sec dashboard API", "frontend": "Run dashboard/web with npm run dev."}


@app.get("/api/meta")
def metadata():
    connection = _connection()
    try:
        total, identified = connection.execute("""SELECT count(*), count(*) FILTER (WHERE json_extract_string(raw_json, '$.source_dataset') IS NOT NULL)
            FROM events""").fetchone()
        source = None
        if total and identified == total:
            source = connection.execute("SELECT json_extract_string(raw_json, '$.source_dataset') FROM events LIMIT 1").fetchone()[0]
        events_path = os.environ.get("HUSH_EVENTS_PATH")
        trace_path = os.environ.get("HUSH_TRACE_PATH")
        tail_enabled = bool(events_path and trace_path and Path(events_path).exists() and Path(trace_path).exists())
        return {"event_count": total, "source_dataset": source, "tail_enabled": tail_enabled}
    finally:
        connection.close()


@app.get("/api/events")
def events(from_: str | None = Query(default=None, alias="from"), to: str | None = None,
           filter: list[str] = Query(default=[]), after_id: int | None = None, limit: int = Query(default=200, ge=1, le=1000)):
    where_range, range_args = _range(from_, to)
    where_filter, filter_args = _filters(filter)
    after_sql = " AND e.event_id < ?" if after_id is not None else ""
    args = range_args + filter_args + ([after_id] if after_id is not None else []) + [limit]
    connection = _connection()
    try:
        rows = connection.execute(f"""SELECT e.event_id,e.timestamp,e.severity,e.src_ip,e.method,e.path,e.status,e.username,e.user_agent,e.session_id,e.raw_json,
            (SELECT w.trace_json FROM windows w WHERE w.event_start <= e.event_id AND w.event_end >= e.event_id ORDER BY w.event_start DESC LIMIT 1)
            FROM events e WHERE {where_range} AND {where_filter}{after_sql} ORDER BY e.event_id DESC LIMIT ?""", args).fetchall()
        next_id = min((row[0] for row in rows), default=None)
        return {"rows": [_event(row) for row in rows], "next_after_id": next_id, "count": len(rows)}
    finally:
        connection.close()


@app.get("/api/replay/batch")
def replay_batch(after_id: int = Query(default=-1), limit: int = Query(default=500, ge=1, le=2000)):
    connection = _connection()
    try:
        max_id = connection.execute("SELECT max(event_id) FROM events").fetchone()[0]
        rows = connection.execute("""SELECT e.event_id,e.timestamp,e.severity,e.src_ip,e.method,e.path,e.status,e.username,e.user_agent,e.session_id,e.raw_json,
            (SELECT w.trace_json FROM windows w WHERE w.event_start <= e.event_id AND w.event_end >= e.event_id ORDER BY w.event_start DESC LIMIT 1)
            FROM events e WHERE e.event_id > ? ORDER BY e.event_id LIMIT ?""", [after_id, limit]).fetchall()
        next_id = max((row[0] for row in rows), default=after_id)
        return {"rows": [_event(row) for row in rows], "next_after_id": next_id,
                "total_events": connection.execute("SELECT count(*) FROM events").fetchone()[0],
                "complete": max_id is None or next_id >= max_id}
    finally:
        connection.close()


@app.get("/api/events/{event_id}")
def event_detail(event_id: int, context: int = Query(default=20, ge=0, le=100)):
    connection = _connection()
    try:
        row = connection.execute("SELECT event_id,timestamp,severity,src_ip,method,path,status,username,user_agent,session_id,raw_json,(SELECT trace_json FROM windows w WHERE w.event_start<=e.event_id AND w.event_end>=e.event_id ORDER BY w.event_start DESC LIMIT 1) FROM events e WHERE event_id=?", [event_id]).fetchone()
        if not row:
            raise HTTPException(404, "Event not found")
        surrounding = connection.execute("SELECT event_id,timestamp,severity,src_ip,method,path,status,username,user_agent,session_id,raw_json,(SELECT trace_json FROM windows w WHERE w.event_start<=e.event_id AND w.event_end>=e.event_id ORDER BY w.event_start DESC LIMIT 1) FROM events e WHERE event_id BETWEEN ? AND ? ORDER BY event_id", [event_id-context, event_id+context]).fetchall()
        return {"event": _event(row), "context": [_event(item) for item in surrounding]}
    finally:
        connection.close()


@app.get("/api/alerts")
def alerts(filter: list[str] = Query(default=[]), from_: str | None = Query(default=None, alias="from"),
           to: str | None = None, through_id: int | None = None,
           window_seconds: int = Query(default=0, ge=0, le=3600), limit: int = Query(default=100, ge=1, le=500)):
    connection = _connection()
    try:
        where_filter, args = _filters(filter)
        range_filter, range_args = _range(from_, to)
        through_filter = " AND a.event_end <= ?" if through_id is not None else ""
        window_filter = ""
        window_args: list[Any] = []
        if window_seconds:
            latest = connection.execute("SELECT max(try_cast(timestamp AS TIMESTAMPTZ)) FROM events WHERE event_id <= ?", [through_id if through_id is not None else 9223372036854775807]).fetchone()[0]
            if latest is None:
                return []
            window_filter = " AND try_cast(e.timestamp AS TIMESTAMPTZ) BETWEEN ? AND ?"
            window_args = [latest-timedelta(seconds=window_seconds), latest]
        rows = connection.execute(f"""SELECT a.alert_id,a.event_start,a.event_end,a.kind,a.confidence,a.evidence_ids,a.gate_reason,a.explanation
          FROM alerts a JOIN events e ON e.event_id=a.event_start JOIN windows w ON w.event_start=a.event_start AND w.event_end=a.event_end
          WHERE {where_filter} AND {range_filter}{through_filter}{window_filter}
          GROUP BY ALL ORDER BY a.event_start DESC LIMIT ?""", args+range_args+([through_id] if through_id is not None else [])+window_args+[limit]).fetchall()
        return [{"alert_id": r[0], "event_start": r[1], "event_end": r[2], "kind": r[3], "confidence": r[4],
                 "evidence_ids": json.loads(r[5]), "gate_reason": r[6], "explanation": json.loads(r[7])} for r in rows]
    finally:
        connection.close()


@app.get("/api/histogram")
def histogram(from_: str | None = Query(default=None, alias="from"), to: str | None = None,
              filter: list[str] = Query(default=[]), buckets: int = Query(default=120, ge=1, le=1000),
              through_id: int | None = None, window_seconds: int = Query(default=0, ge=0, le=3600)):
    where_range, range_args = _range(from_, to)
    where_filter, filter_args = _filters(filter)
    through_filter = " AND e.event_id <= ?" if through_id is not None else ""
    through_args = [through_id] if through_id is not None else []
    connection = _connection()
    try:
        bounds = connection.execute(f"SELECT min(try_cast(timestamp AS TIMESTAMPTZ)),max(try_cast(timestamp AS TIMESTAMPTZ)) FROM events e WHERE {where_range} AND {where_filter}{through_filter}", range_args+filter_args+through_args).fetchone()
        if not bounds or bounds[0] is None:
            return {"buckets": [], "alerts": [], "spike_bands": []}
        if window_seconds:
            end = bounds[1]
            start = end-timedelta(seconds=window_seconds)
            window_filter = " AND try_cast(e.timestamp AS TIMESTAMPTZ) BETWEEN ? AND ?"
            window_args: list[Any] = [start, end]
        else:
            start, end = bounds
            window_filter = ""
            window_args = []
        duration = float(window_seconds) if window_seconds else max((end-start).total_seconds(), 1.0)
        width = duration / buckets
        rows = connection.execute(f"""SELECT least({buckets - 1}, floor(date_diff('millisecond', ?, try_cast(e.timestamp AS TIMESTAMPTZ)) / ?)) AS bucket,
            count(*) FILTER (WHERE severity='info'), count(*) FILTER (WHERE severity='warning'), count(*) FILTER (WHERE severity='error')
            FROM events e WHERE {where_range} AND {where_filter}{through_filter}{window_filter} GROUP BY bucket ORDER BY bucket""", [start, width*1000]+range_args+filter_args+through_args+window_args).fetchall()
        grouped = {int(r[0]): (r[1], r[2], r[3]) for r in rows}
        points = [{"index": index, "t": (start.timestamp()+index*width)*1000,
                   "info": grouped.get(index, (0, 0, 0))[0], "warning": grouped.get(index, (0, 0, 0))[1],
                   "error": grouped.get(index, (0, 0, 0))[2], "alert_marker": None, "alert_event_start": None}
                  for index in range(buckets)]
        counts = [p["info"]+p["warning"]+p["error"] for p in points]
        mean_count = sum(counts)/len(counts) if counts else 0
        threshold = mean_count + 3 * (mean_count ** 0.5)
        spike_bands = [{"from": i, "to": i} for i, count in enumerate(counts) if count >= max(1, threshold)]
        alert_where, alert_args = _filters(filter)
        alert_range, alert_range_args = _range(from_, to)
        alert_through = " AND a.event_end <= ?" if through_id is not None else ""
        alert_window = " AND try_cast(e.timestamp AS TIMESTAMPTZ) BETWEEN ? AND ?" if window_seconds else ""
        alert_rows = connection.execute(f"""SELECT a.alert_id,a.event_start,a.event_end,a.kind,e.timestamp FROM alerts a
          JOIN events e ON e.event_id=a.event_start WHERE {alert_where} AND {alert_range}{alert_through}{alert_window} ORDER BY a.event_start""", alert_args+alert_range_args+through_args+window_args).fetchall()
        alert_markers = []
        for alert in alert_rows:
            stamp = int(datetime.fromisoformat(alert[4].replace("Z", "+00:00")).timestamp()*1000)
            index = min(buckets-1, max(0, int(((stamp/1000)-start.timestamp())/width)))
            point = points[index]
            point["alert_marker"] = max(1, point["info"]+point["warning"]+point["error"])
            point["alert_event_start"] = int(alert[1])
            alert_markers.append({"alert_id": alert[0], "event_start": alert[1], "event_end": alert[2], "kind": alert[3], "t": stamp})
        return {"buckets": points, "alerts": alert_markers, "spike_bands": spike_bands, "range": {"from": int(start.timestamp()*1000), "to": int(end.timestamp()*1000)}}
    finally:
        connection.close()


@app.get("/api/truth/{stream_id}")
def truth_overlay(stream_id: str, enabled: bool = False):
    if not enabled:
        return {"enabled": False, "episodes": []}
    from .truth import episodes
    try:
        return {"enabled": True, "episodes": episodes(stream_id)}
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/tail")
def tail(after_id: int = 0):
    def updates():
        last_id = after_id
        last_window_count = -1
        while True:
            connection = _connection()
            try:
                rows = connection.execute("SELECT event_id,timestamp,severity,src_ip,method,path,status,username,user_agent,session_id,raw_json,(SELECT trace_json FROM windows w WHERE w.event_start<=e.event_id AND w.event_end>=e.event_id ORDER BY w.event_start DESC LIMIT 1) FROM events e WHERE event_id>? ORDER BY event_id LIMIT 500", [last_id]).fetchall()
                window_count = connection.execute("SELECT count(*) FROM windows").fetchone()[0]
                if rows or window_count != last_window_count:
                    events_batch = [_event(row) for row in rows]
                    if events_batch:
                        last_id = events_batch[-1]["event_id"]
                    last_window_count = window_count
                    yield "data: "+json.dumps({"events": events_batch}, ensure_ascii=False)+"\n\n"
                else:
                    yield ": keep-alive\n\n"
            finally:
                connection.close()
            time.sleep(1)
    return StreamingResponse(updates(), media_type="text/event-stream", headers={"Cache-Control":"no-cache", "X-Accel-Buffering":"no"})
