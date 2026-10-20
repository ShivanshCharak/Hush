# Dashboard

The dashboard is a Next.js App Router frontend using Tailwind CSS, TanStack Query, TanStack Table, TanStack Virtual, and Recharts. Its FastAPI service reads a local DuckDB snapshot. The service runs separately from Next.js; the Next rewrite proxies `/api/*` to `http://127.0.0.1:8000` by default.

## Load a replay

From the repository root, replay a stream and save its decision trace:

```bash
python pipeline/run.py data/streams/stream_01.jsonl --trace dashboard/data/stream_01_trace.jsonl
python dashboard/api/ingest.py data/streams/stream_01.jsonl dashboard/data/stream_01_trace.jsonl
```

For a static snapshot, start the API with:

```bash
python -m uvicorn dashboard.api.routes:app --host 127.0.0.1 --port 8000
```

Install frontend dependencies and start Next.js in another terminal:

```bash
cd dashboard/web
npm install
npm run dev
```

Open `http://localhost:3000`. Set `DASHBOARD_API_ORIGIN` if the API uses a different address. The DuckDB file is written to `dashboard/data/dashboard.duckdb` by default; override it with `HUSH_DASHBOARD_DB`.

## View the real ModSecurity archive

The dashboard's archive view uses the converted public ModSecurity requests from `data/external/modsecurity_events.jsonl`, stored in a local DuckDB snapshot. Its detector trace is generated locally by this project; it is not a source-provided label, and the source archive is not a live feed.

```bash
python pipeline/run.py data/external/modsecurity_events.jsonl --trace dashboard/data/modsecurity-trace.jsonl
python dashboard/api/ingest.py data/external/modsecurity_events.jsonl dashboard/data/modsecurity-trace.jsonl --database dashboard/data/modsecurity.duckdb
HUSH_DASHBOARD_DB="$PWD/dashboard/data/modsecurity.duckdb" python -m uvicorn dashboard.api.routes:app --host 127.0.0.1 --port 8000
```

Start Next.js in another terminal as above. The UI identifies this as an imported archive snapshot and shows its event count; the Live tail control remains disabled until append-only event and trace paths are configured.

## Live demo replay

Initialize empty event and trace files and the DuckDB snapshot, then start FastAPI with the tail paths configured:

```bash
mkdir -p dashboard/data
: > dashboard/data/demo-events.jsonl
: > dashboard/data/demo-trace.jsonl
python dashboard/api/ingest.py dashboard/data/demo-events.jsonl dashboard/data/demo-trace.jsonl
HUSH_EVENTS_PATH="$PWD/dashboard/data/demo-events.jsonl" HUSH_TRACE_PATH="$PWD/dashboard/data/demo-trace.jsonl" python -m uvicorn dashboard.api.routes:app --host 127.0.0.1 --port 8000
```

In another terminal run `python demo/replay.py`. It writes 900 events over 180 seconds and appends a decision row after each 20-event window. Use `--speed 20` for a faster rehearsal; the evaluator checks deterministic trace output separately from wall-clock timing. Start the Next.js app as above and enable **Live tail**. Use a fresh, empty database for each replay because event IDs restart at zero.

Run `python eval/phase4_eval.py` for a dev-only injection, canary, truth-separation, and deterministic demo preflight report. Pass `--model` to measure the currently configured Ollama model instead of the rules baseline. The default baseline evaluation replays three deterministic traces; paced 180-second rehearsals still need to be run separately. Do not use this command against the locked test set.

## Features

- URL-backed key-value filters, clickable event values, severity histogram, spike bands, alert markers, keyset pagination, and a virtualized request table.
- Event detail with raw JSON, surrounding events, detector verdict, gate reason, confidence, and explanation.
- Alert cards link back to their source range and highlight cited evidence rows.
- SSE live tail reads event and trace JSONL appends when `HUSH_EVENTS_PATH` and `HUSH_TRACE_PATH` are set before FastAPI starts.
- Ground-truth episodes are served only by the dashboard's explicit opt-in dev-stream endpoint and are disabled in live mode by default.

The ingester builds an initial snapshot. When `HUSH_EVENTS_PATH` and `HUSH_TRACE_PATH` point to append-only JSONL files at API startup, a background watcher adds complete new lines to DuckDB; the SSE endpoint publishes newly indexed events. This is the actual streaming mode, distinct from browsing an archived dataset. Use a new database for each replay because the demo restarts event IDs at zero.

DuckDB is used as an embedded, serverless analytical store: it simplifies local setup and supports fast columnar filtering, time-bucket aggregation, and paginated log queries without a separately managed database server. It suits this local archive/replay explorer, not a high-write, multi-tenant production event-ingestion service.
