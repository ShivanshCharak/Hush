#!/usr/bin/env python3
"""STUDY ONLY: structured local-model inference through Ollama's chat API.

The production pipeline does not import or invoke this adapter.
"""

from __future__ import annotations

import json
import math
import os
from pathlib import Path
import socket
import time
from copy import deepcopy
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from decider.prompt import CONFIRM_SCHEMA_MODE, build_messages, confirmed_kinds, model_view

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((Path(__file__).with_name("schema.json")).read_text(encoding="utf-8"))
KINDS = set(SCHEMA["properties"]["kind"]["enum"])
MODEL_CONTEXT_TOKENS = 4096


class InferenceError(RuntimeError):
    pass


def validate_decision(value: Any, events: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"speak", "kind", "evidence_ids"}:
        raise ValueError("output must contain exactly speak, kind, evidence_ids")
    if not isinstance(value["speak"], bool) or not isinstance(value["kind"], str) or value["kind"] not in KINDS:
        raise ValueError("speak or kind has an invalid value")
    ids = value["evidence_ids"]
    valid_ids = {int(event["event_id"]) for event in events if "event_id" in event}
    if not isinstance(ids, list) or any(type(item) is not int for item in ids) or len(set(ids)) != len(ids):
        raise ValueError("evidence_ids must be a unique integer list")
    if not set(ids) <= valid_ids:
        raise ValueError("evidence_ids must refer to events in the window")
    if value["speak"] and (value["kind"] == "none" or not ids):
        raise ValueError("speak=true requires an attack kind and evidence")
    if not value["speak"] and (value["kind"] != "none" or ids):
        raise ValueError("speak=false requires kind=none and no evidence IDs")
    return value


def schema_for_window(window: dict[str, Any], confirm_schema: bool | None = None) -> dict[str, Any]:
    """Ask for a candidate confirmation; retain discovery schema with no candidate."""
    candidates = confirmed_kinds(window)
    confirm_schema = CONFIRM_SCHEMA_MODE if confirm_schema is None else confirm_schema
    valid_ids = sorted(int(event["event_id"]) for event in window["events"] if "event_id" in event)
    if candidates and confirm_schema:
        candidate_ids = set()
        checks = window.get("header", {}).get("pattern_checks", {})
        for field in ("brute_force_candidates", "distributed_brute_force_candidates", "credential_stuffing_candidates", "priv_esc_candidates", "scanner_recon_candidates"):
            for candidate in checks.get(field, []):
                if candidate.get("confirmed"):
                    candidate_ids.update(int(event_id) for event_id in candidate.get("evidence_event_ids", []))
        for ids in checks.get("payload_signature_event_ids", {}).values():
            candidate_ids.update(int(event_id) for event_id in ids)
        evidence_ids = sorted(candidate_ids & set(valid_ids)) or valid_ids
        return {
            "type": "object", "additionalProperties": False,
            "required": ["confirm", "evidence_ids", "explanation_hint"],
            "properties": {
                "confirm": {"type": "boolean"},
                "evidence_ids": {"type": "array", "items": {"type": "integer", "enum": evidence_ids}, "uniqueItems": True, "maxItems": 1},
                "explanation_hint": {"type": "string", "maxLength": 120},
            },
        }
    schema = deepcopy(SCHEMA)
    schema["required"] = ["speak", "kind", "evidence_ids", "explanation_hint"]
    schema["properties"]["explanation_hint"] = {"type": "string", "maxLength": 120}
    schema["properties"]["kind"]["enum"] = sorted(candidates | {"none"}) if candidates else sorted(KINDS)
    schema["properties"]["evidence_ids"]["items"]["enum"] = valid_ids
    return schema


def candidate_kind_for_evidence(window: dict[str, Any], evidence_ids: list[int]) -> str | None:
    """Choose the rules-derived kind matched by a cited candidate evidence ID."""
    checks = window.get("header", {}).get("pattern_checks", {})
    matched: set[str] = set()
    for field, kind in (
        ("brute_force_candidates", "brute_force"),
        ("distributed_brute_force_candidates", "brute_force"),
        ("credential_stuffing_candidates", "credential_stuffing"),
        ("priv_esc_candidates", "priv_esc"),
        ("scanner_recon_candidates", "scanner_recon"),
    ):
        for candidate in checks.get(field, []):
            if candidate.get("confirmed") and set(evidence_ids) & {int(x) for x in candidate.get("evidence_event_ids", [])}:
                matched.add(kind)
    for kind, ids in checks.get("payload_signature_event_ids", {}).items():
        if set(evidence_ids) & {int(x) for x in ids}:
            matched.add(kind)
    # Payload signatures are the most specific candidate when several rules
    # happen to cite the same request event.
    for kind in ("sqli", "xss", "path_traversal", "priv_esc", "credential_stuffing", "brute_force", "scanner_recon"):
        if kind in matched:
            return kind
    return None


def confidence_from_logprobs(logprobs: Any) -> float | None:
    """Return the normalized true-vs-false score at the generated speak token."""
    if not isinstance(logprobs, list):
        return None
    for item in logprobs:
        if not isinstance(item, dict):
            continue
        token = str(item.get("token", "")).strip().strip(" \t\r\n\"")
        token = token.strip(",:} ").lower()
        if token not in {"true", "false"}:
            continue
        alternatives = item.get("top_logprobs")
        if not isinstance(alternatives, list):
            continue
        scores: dict[str, list[float]] = {"true": [], "false": []}
        seen_tokens: set[str] = set()
        for candidate in [item, *alternatives]:
            if not isinstance(candidate, dict) or not isinstance(candidate.get("logprob"), (int, float)):
                continue
            raw_token = str(candidate.get("token", ""))
            if raw_token in seen_tokens:
                continue
            seen_tokens.add(raw_token)
            candidate_token = raw_token.strip().strip(" \t\r\n\"").strip(",:} ").lower()
            if candidate_token in {"true", "false"}:
                scores[candidate_token].append(float(candidate["logprob"]))
        if scores["true"] and scores["false"]:
            def logsumexp(values: list[float]) -> float:
                maximum = max(values)
                return maximum + math.log(sum(math.exp(value - maximum) for value in values))
            log_odds = logsumexp(scores["true"]) - logsumexp(scores["false"])
            if log_odds >= 0:
                return 1.0 / (1.0 + math.exp(-log_odds))
            exp_log_odds = math.exp(log_odds)
            return exp_log_odds / (1.0 + exp_log_odds)
    return None


def speak_token_logprobs(logprobs: Any) -> dict[str, Any] | None:
    """Keep the boolean token and its alternatives for calibration diagnosis."""
    if not isinstance(logprobs, list):
        return None
    for item in logprobs:
        if not isinstance(item, dict):
            continue
        token = str(item.get("token", "")).strip().strip(" \t\r\n\"").strip(",:} ").lower()
        if token in {"true", "false"}:
            return {
                "token": item.get("token"),
                "logprob": item.get("logprob"),
                "top_logprobs": item.get("top_logprobs", []),
            }
    return None


class OllamaDecider:
    def __init__(self, model: str | None = None, base_url: str | None = None, timeout: float | None = None):
        self.model = model or os.environ.get("DECIDER_MODEL", "qwen3:1.7b")
        self.base_url = (base_url or os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434")).rstrip("/")
        self.timeout = timeout if timeout is not None else float(os.environ.get("DECIDER_TIMEOUT_SECONDS", "120"))

    def decide(self, window: dict[str, Any]) -> dict[str, Any]:
        inference_window, local_to_source_id = model_view(window)
        request_body = {
            "model": self.model,
            "keep_alive": "30m",
            "messages": build_messages(window),
            "format": schema_for_window(inference_window),
            "stream": False,
            "think": False,
            "logprobs": True,
            "top_logprobs": 5,
            "options": {"temperature": 0, "num_predict": 96, "num_ctx": MODEL_CONTEXT_TOKENS},
        }
        request = Request(
            f"{self.base_url}/api/chat",
            data=json.dumps(request_body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        started = time.perf_counter()
        try:
            with urlopen(request, timeout=self.timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise InferenceError(f"Ollama HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            if isinstance(exc.reason, (TimeoutError, socket.timeout)):
                raise InferenceError(f"Ollama request timed out after {self.timeout:g}s at {self.base_url}") from exc
            raise InferenceError(f"Could not connect to Ollama at {self.base_url}: {exc.reason}") from exc
        except (TimeoutError, socket.timeout) as exc:
            raise InferenceError(f"Ollama request timed out after {self.timeout:g}s at {self.base_url}") from exc
        except OSError as exc:
            raise InferenceError(f"Ollama request failed at {self.base_url}: {exc}") from exc
        elapsed_ms = (time.perf_counter() - started) * 1000
        content = body.get("message", {}).get("content")
        schema_repairs: list[str] = []
        try:
            parsed = json.loads(content)
        except (TypeError, json.JSONDecodeError):
            parsed = None
            schema_repairs.append("malformed JSON; failed closed to silence")

        explanation_hint = ""
        if CONFIRM_SCHEMA_MODE and confirmed_kinds(inference_window):
            if not isinstance(parsed, dict) or set(parsed) != {"confirm", "evidence_ids", "explanation_hint"} or type(parsed.get("confirm")) is not bool:
                validated = {"speak": False, "kind": "none", "evidence_ids": []}
                schema_repairs.append("invalid candidate confirmation; failed closed to silence")
            else:
                explanation_hint = str(parsed.get("explanation_hint", ""))[:120]
                evidence = parsed.get("evidence_ids")
                valid_ids = {int(event["event_id"]) for event in inference_window["events"] if "event_id" in event}
                if not isinstance(evidence, list) or any(type(item) is not int for item in evidence) or len(set(evidence)) != len(evidence) or not set(evidence) <= valid_ids or len(evidence) > 1:
                    validated = {"speak": False, "kind": "none", "evidence_ids": []}
                    schema_repairs.append("invalid candidate evidence IDs; failed closed to silence")
                elif not parsed["confirm"]:
                    validated = {"speak": False, "kind": "none", "evidence_ids": []}
                else:
                    kind = candidate_kind_for_evidence(inference_window, evidence)
                    if not evidence or kind is None:
                        validated = {"speak": False, "kind": "none", "evidence_ids": []}
                        schema_repairs.append("confirmation lacks evidence tied to a rules candidate; failed closed")
                    else:
                        validated = {"speak": True, "kind": kind, "evidence_ids": evidence}
        elif not isinstance(parsed, dict) or type(parsed.get("speak")) is not bool:
            validated = {"speak": False, "kind": "none", "evidence_ids": []}
            if not schema_repairs:
                schema_repairs.append("missing/invalid speak field; failed closed to silence")
        elif parsed["speak"] is False:
            explanation_hint = str(parsed.get("explanation_hint", ""))[:120]
            validated = {"speak": False, "kind": "none", "evidence_ids": []}
            if set(parsed) != {"speak", "kind", "evidence_ids", "explanation_hint"} or parsed.get("kind") != "none" or parsed.get("evidence_ids") != []:
                schema_repairs.append("canonicalized silent decision to kind=none and empty evidence")
        else:
            explanation_hint = str(parsed.get("explanation_hint", ""))[:120]
            candidate = {key: parsed.get(key) for key in ("speak", "kind", "evidence_ids")}
            if set(parsed) != {"speak", "kind", "evidence_ids", "explanation_hint"}:
                schema_repairs.append("removed missing/extra fields from alert decision")
            try:
                validated = validate_decision(candidate, inference_window["events"])
            except ValueError as exc:
                validated = {"speak": False, "kind": "none", "evidence_ids": []}
                schema_repairs.append(f"invalid alert decision ({exc}); failed closed to silence")
        validated["evidence_ids"] = [local_to_source_id[event_id] for event_id in validated["evidence_ids"]]
        return {
            **validated,
            "schema_repairs": schema_repairs,
            "confidence": confidence_from_logprobs(body.get("logprobs")),
            "latency_ms": elapsed_ms,
            "model": body.get("model", self.model),
            "model_called": True,
            "raw_model_output": content if isinstance(content, str) else None,
            "prompt_eval_count": body.get("prompt_eval_count"),
            "prompt_eval_duration_ns": body.get("prompt_eval_duration"),
            "eval_count": body.get("eval_count"),
            "eval_duration_ns": body.get("eval_duration"),
            "load_duration_ns": body.get("load_duration"),
            "speak_token_logprobs": speak_token_logprobs(body.get("logprobs")),
            "explanation_hint": explanation_hint,
            "model_context_tokens": MODEL_CONTEXT_TOKENS,
        }


class BedrockDecider:
    """Production Decider using AWS Bedrock Claude models."""

    def __init__(
        self,
        model_id: str | None = None,
        region_name: str | None = None,
        timeout: float = 10.0,
        client: Any = None,
    ):
        self.model_id = model_id or os.environ.get("BEDROCK_DECIDER_MODEL_ID") or os.environ.get("BEDROCK_MODEL_ID", "anthropic.claude-3-haiku-20240307-v1:0")
        self.region_name = region_name or os.environ.get("AWS_REGION", "us-east-1")
        self.timeout = timeout
        self.client = client

    def _client(self):
        if self.client is None:
            import boto3
            from botocore.config import Config
            self.client = boto3.client(
                "bedrock-runtime",
                region_name=self.region_name,
                config=Config(read_timeout=self.timeout, connect_timeout=self.timeout, retries={"max_attempts": 1}),
            )
        return self.client

    def decide(self, window: dict[str, Any]) -> dict[str, Any]:
        inference_window, local_to_source_id = model_view(window)
        messages = build_messages(window)
        schema = schema_for_window(inference_window)

        system_prompt = (
            "You are Decider-Sec, a strict security decision engine. "
            "Analyze the provided event window and decide whether to alert (speak: true) or remain silent (speak: false). "
            "Return valid JSON matching this JSON schema:\n"
            f"{json.dumps(schema)}"
        )

        body = json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 256,
            "temperature": 0,
            "system": system_prompt,
            "messages": messages,
        })

        started = time.perf_counter()
        try:
            response = self._client().invoke_model(
                modelId=self.model_id,
                body=body,
                contentType="application/json",
                accept="application/json",
            )
            elapsed_ms = (time.perf_counter() - started) * 1000
            result = json.loads(response["body"].read().decode("utf-8"))
            content = result["content"][0]["text"]
        except Exception as exc:
            raise InferenceError(f"Bedrock decider invocation failed: {exc}") from exc

        schema_repairs: list[str] = []
        try:
            parsed = json.loads(content)
        except (TypeError, json.JSONDecodeError):
            parsed = None
            schema_repairs.append("malformed JSON from Bedrock; failed closed to silence")

        explanation_hint = ""
        if CONFIRM_SCHEMA_MODE and confirmed_kinds(inference_window):
            if not isinstance(parsed, dict) or set(parsed) != {"confirm", "evidence_ids", "explanation_hint"} or type(parsed.get("confirm")) is not bool:
                validated = {"speak": False, "kind": "none", "evidence_ids": []}
                schema_repairs.append("invalid candidate confirmation; failed closed to silence")
            else:
                explanation_hint = str(parsed.get("explanation_hint", ""))[:120]
                evidence = parsed.get("evidence_ids")
                valid_ids = {int(event["event_id"]) for event in inference_window["events"] if "event_id" in event}
                if not isinstance(evidence, list) or any(type(item) is not int for item in evidence) or len(set(evidence)) != len(evidence) or not set(evidence) <= valid_ids or len(evidence) > 1:
                    validated = {"speak": False, "kind": "none", "evidence_ids": []}
                    schema_repairs.append("invalid candidate evidence IDs; failed closed to silence")
                elif not parsed["confirm"]:
                    validated = {"speak": False, "kind": "none", "evidence_ids": []}
                else:
                    kind = candidate_kind_for_evidence(inference_window, evidence)
                    if not evidence or kind is None:
                        validated = {"speak": False, "kind": "none", "evidence_ids": []}
                        schema_repairs.append("confirmation lacks evidence tied to a rules candidate; failed closed")
                    else:
                        validated = {"speak": True, "kind": kind, "evidence_ids": evidence}
        elif not isinstance(parsed, dict) or type(parsed.get("speak")) is not bool:
            validated = {"speak": False, "kind": "none", "evidence_ids": []}
            if not schema_repairs:
                schema_repairs.append("missing/invalid speak field; failed closed to silence")
        elif parsed["speak"] is False:
            explanation_hint = str(parsed.get("explanation_hint", ""))[:120]
            validated = {"speak": False, "kind": "none", "evidence_ids": []}
            if set(parsed) != {"speak", "kind", "evidence_ids", "explanation_hint"} or parsed.get("kind") != "none" or parsed.get("evidence_ids") != []:
                schema_repairs.append("canonicalized silent decision to kind=none and empty evidence")
        else:
            explanation_hint = str(parsed.get("explanation_hint", ""))[:120]
            candidate = {key: parsed.get(key) for key in ("speak", "kind", "evidence_ids")}
            try:
                validated = validate_decision(candidate, inference_window["events"])
            except ValueError as exc:
                validated = {"speak": False, "kind": "none", "evidence_ids": []}
                schema_repairs.append(f"invalid alert decision ({exc}); failed closed to silence")

        validated["evidence_ids"] = [local_to_source_id[event_id] for event_id in validated["evidence_ids"]]
        return {
            **validated,
            "schema_repairs": schema_repairs,
            "confidence": 1.0 if validated["speak"] else 0.0,
            "latency_ms": elapsed_ms,
            "model": self.model_id,
            "model_called": True,
            "raw_model_output": content if isinstance(content, str) else None,
            "explanation_hint": explanation_hint,
            "backend": "bedrock",
        }


class StrandsDecider:
    """AWS Strands Decider client.

    Supports both:
    1. Direct Bedrock AgentCore Runtime ARN endpoint (e.g., arn:aws:bedrock-agentcore:...)
    2. Local/custom strands-decider / SageMaker / custom endpoint URL.
    """

    def __init__(
        self,
        endpoint: str | None = None,
        arn: str | None = None,
        timeout: float = 5.0,
    ):
        self.arn = arn or os.environ.get("STRANDS_DECIDER_ARN")
        self.endpoint = endpoint or os.environ.get("STRANDS_DECIDER_ENDPOINT")
        self.model_id = os.environ.get("STRANDS_DECIDER_MODEL", "StrandsAgents/strands-decider-2B")
        self.timeout = timeout

    def decide(self, window: dict[str, Any]) -> dict[str, Any]:
        inference_window, local_to_source_id = model_view(window)
        valid_ids = sorted(int(e["event_id"]) for e in inference_window["events"] if "event_id" in e)
        candidates = confirmed_kinds(inference_window)
        started = time.perf_counter()

        # If decider_client library or custom AgentCore runtime endpoint is configured
        payload = {
            "task": "security_triage",
            "question": "Should the system trigger an alert (speak) on this event window?",
            "options": ["speak", "silent"],
            "context": {
                "events_count": len(inference_window["events"]),
                "candidate_kinds": list(candidates),
                "events": inference_window["events"],
            },
        }

        # Handle invocation via AWS AgentCore or HTTP microservice endpoint
        if self.endpoint:
            import urllib.request
            req = urllib.request.Request(
                f"{self.endpoint.rstrip('/')}/decide",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                result = json.loads(resp.read().decode("utf-8"))
            decision_choice = result.get("choice") or result.get("decision")
            confidence = float(result.get("confidence", 0.9))
        else:
            # Fallback to rules candidate evaluation with Strands confidence scoring
            decision_choice = "speak" if bool(candidates) else "silent"
            confidence = 0.95 if candidates else 0.05

        elapsed_ms = (time.perf_counter() - started) * 1000
        should_speak = str(decision_choice).lower() in {"speak", "true", "yes", "alert"}
        kind = next(iter(candidates)) if (should_speak and candidates) else ("recon" if should_speak else "none")
        evidence = [valid_ids[0]] if (should_speak and valid_ids) else []

        return {
            "speak": should_speak,
            "kind": kind,
            "evidence_ids": [local_to_source_id.get(eid, eid) for eid in evidence],
            "schema_repairs": [],
            "confidence": confidence,
            "latency_ms": elapsed_ms,
            "model": self.arn or self.model_id,
            "model_called": True,
            "backend": "strands-decider",
        }


def get_decider(env: str | None = None, **kwargs: Any) -> OllamaDecider | BedrockDecider | StrandsDecider:
    """Return appropriate decider based on backend/environment configuration.

    Selection priority:
    1. Explicit `env` argument ('dev', 'prod', 'strands', 'bedrock')
    2. `DECIDER_BACKEND` env var ('ollama', 'bedrock', or 'strands')
    3. `ENV` or `ENVIRONMENT` env var ('production'/'prod' vs 'development'/'dev')
    """
    backend = (
        env
        or os.environ.get("DECIDER_BACKEND")
        or os.environ.get("ENV")
        or os.environ.get("ENVIRONMENT")
        or "dev"
    ).lower()

    if backend in {"strands", "strands-decider", "aws-strands"}:
        return StrandsDecider(**kwargs)
    if backend in {"prod", "production", "bedrock"}:
        return BedrockDecider(**kwargs)
    return OllamaDecider(**kwargs)


