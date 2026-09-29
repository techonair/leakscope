# LeakScope

Open-source, explainable leak triage for SOC teams. LeakScope consumes scanner output and turns an item into a masked, fingerprinted record with deterministic evidence and a conservative disposition.

## v0.1 status

This repository contains the local triage core, JSON/JSONL/plain-text CLI, HTTP API, and a local single-item analyst console. Supported deterministic patterns currently include AWS access key IDs, GitHub tokens, JWT structure, PEM private-key blocks, and Luhn-valid payment card numbers. Placeholder detection, optional organisation-domain matching, HMAC fingerprints, versioned Jev questions, and configurable policy rules are included.

Jev is integrated through its documented System One REST API. Set `JEV_API_KEY` in the server environment to enable it; without a key, when the provider fails, or when typed answers are invalid, items go to `REVIEW`. The pinned default model is `typesafe/jev-1.13`; set `JEV_MODEL` to change it deliberately. Requests contain masked text and deterministic facts only, never the original values matched by supported detectors. Question IDs, model ID, validated answers, and policy version are retained in the triage response. The 12-question set is sent as batches of at most eight questions.

No credential is tested, no case is persisted, and no benchmark performance claim is made. Detector coverage is intentionally incomplete; do not treat missing evidence as proof that an item is safe. Review Jev's retention terms and your organization's data-handling requirements before sending even masked content to the hosted API.

## Run locally

Requires Python 3.11 or newer.

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
$env:JEV_API_KEY = "your-server-side-jev-key"
uvicorn leakscope.api:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/` for the analyst console. It submits one item directly to the local API and does not save a queue or history. You can also submit an item to `POST /v1/triage` with JSON such as `{"text":"possible leaked value"}`. The API returns masked text, deterministic evidence, Jev's typed answers when available, a policy level, and provenance. The local API has no authentication; bind it to loopback and do not expose it to a network. Create/manage API keys at [the Jev API key page](https://thejevai.com/settings/apikeys); never put a key in browser code or commit it.

For stable fingerprints across restarts, set `LEAKESCOPE_FINGERPRINT_KEY` to a random value of at least 32 bytes and protect it like a secret. Without it, a random process-local key is used and fingerprints will change on restart. Set `LEAKESCOPE_ORG_DOMAINS` to a comma-separated domain list for deterministic domain matching; that match does not itself prove ownership. Configure a canary fingerprint using `LEAKESCOPE_CANARY_FINGERPRINT_0` and subsequent indexed variables. These use the same HMAC key as item fingerprints.

Triage a JSON, JSONL, or plain-text file:

```powershell
leakscope triage .\alerts.json
```

## Development

```powershell
python -m pip install -e ".[dev]"
pytest
ruff check .
```

Questions live in `questions/v1.yaml`; policy is in `policies/default.yaml`. Tests mock the Jev endpoint and verify that raw supported secrets never appear in outbound state. Before production use, review [Jev's API docs](https://thejevai.com/docs), retention terms, model limitations, and add calibration and adversarial evaluation rather than treating model probabilities as fixed truth.

## Roadmap

Next: scanner-specific ingestion, a richer detector and validation suite, an analyst queue, and LeakBench synthetic baselines. These are not implemented yet. The project will claim model or benchmark superiority only when reproducible LeakBench results support it.

## Responsible use

Use only to defend your organisation or authorised clients. Do not exploit or redistribute leaked data. LeakScope is not legal advice and is not a credential verifier. See [SECURITY.md](SECURITY.md) for reporting and operational boundaries.
