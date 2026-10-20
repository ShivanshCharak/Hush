# Decider implementation notes

`window.py` computes failed-login counts by IP, distinct usernames by IP, and the fraction of 4xx responses. `prefilter.py` keeps failed authentication events and requests containing attack signatures, sensitive-path probes, likely scanner traffic, profile-ID accesses, or server errors. It must retain at least one event from every attack episode in the three dev streams while dropping at least 90% of all events.

`prompt.py` keeps instructions in the system message and places JSON-encoded logs inside an explicit untrusted-data block. No examples are included, avoiding evaluation windows as few-shot examples. `schema.json` is passed to Ollama as the structured-output format. `decide.py` validates the output and evidence IDs and uses the selected `true`/`false` token log probability as confidence; it returns no confidence when the local runtime omits that token probability.

Never load test windows or held-out streams in Phase 2. The implementation uses Ollama's `/api/chat` endpoint with JSON Schema format and `logprobs` enabled.
