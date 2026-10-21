# Local-model study code

This directory contains the Ollama adapter, prompt, schema, and window-header code retained for historical experiments. `decider/decide.py` is not imported by `pipeline/run.py` and is not part of the alert path. Historical results remain in `eval/runs/`; the original `eval/phase2_eval.py` and `eval/phase2_requested_eval.py` are study evaluators.

## Production alert path

The production pipeline always uses deterministic rules to decide and emit alerts. `explain/bedrock.py` uses Bedrock only when explicitly enabled with `--bedrock` or an evaluator's guarded `--real-explainer` option; otherwise it supplies a deterministic template. Bedrock failures also fall back to the template. Explanations cannot create, alter, or suppress alerts.

## Historical local-model experiments

`DECIDER_MODEL`, `OLLAMA_BASE_URL`, and `DECIDER_TIMEOUT_SECONDS` configure only explicit study runs. The adapter validates its historical structured response schema and evidence IDs. Do not use its `speak` output as an alert decision.

The low-memory Ollama notes below apply only when reproducing those studies. On a limited-RAM host, llama-server's host-memory prompt cache can grow to its default 8 GiB even when `OLLAMA_NUM_PARALLEL=1`. For the project machine, cap it at 1 GiB with `Environment="LLAMA_ARG_CACHE_RAM=1024"` in the Ollama service override. This tradeoff increases prompt recomputation and latency. See the [upstream Ollama issue](https://github.com/ollama/ollama/issues/18264).
