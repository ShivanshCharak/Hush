# Decider implementation notes

This directory contains historical local-model study code. It is not on the production pipeline path. `window.py` still provides shared, deterministic feature helpers; the pipeline's alert decisions come only from `baseline/rules.py`.

`prompt.py`, `schema.json`, and `decide.py` support archived experiments only. Model `speak` outputs must never be wired into alert inclusion or suppression.

Never load test windows or held-out streams. Ollama calls belong only to explicit study evaluations, not the production pipeline.
