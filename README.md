# LeakScope

Open-source, explainable leak triage for SOC teams. LeakScope consumes scanner output and turns an item into a masked, fingerprinted record with deterministic evidence and a conservative disposition.

## v0.1 status

This repository contains the local triage core, JSON/JSONL/plain-text CLI, HTTP API, and a local single-item analyst console. Supported deterministic patterns currently include AWS access key IDs, GitHub tokens, JWT structure, PEM private-key blocks, and Luhn-valid payment card numbers. Placeholder detection, optional organisation-domain matching, HMAC fingerprints, configurable policy rules, and versioned questions are included.

The Jev integration is an adapter boundary only: no model call is configured or made. Sensitive-looking material therefore goes to `REVIEW`; the engine does not invent ownership, impact, or confidence. No credential is tested, no secret is persisted, and no benchmark performance claim is made. Detector coverage is intentionally incomplete; do not treat missing evidence as proof that an item is safe.

## Run locally

Requires Python 3.11 or newer.

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
uvicorn leakscope.api:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/` for the analyst console. It submits one item directly to the local API and does not save a queue or history. You can also submit an item to `POST /v1/triage` with JSON such as `{"text":"possible leaked value"}`. The API returns masked text, evidence kinds, a policy level, and provenance. The local API has no authentication; bind it to loopback and do not expose it to a network.

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

Questions live in `questions/v1.yaml`; policy is in `policies/default.yaml`. Any classifier adapter must receive masked state only. Before enabling a provider, review its retention terms, threat model, and the current Jev model limitations; then add calibration and adversarial evaluation rather than treating model probabilities as fixed truth.

## Roadmap

Next: scanner-specific ingestion, a richer detector and validation suite, an analyst queue, a real provider adapter behind explicit configuration, and LeakBench synthetic baselines. These are not implemented yet. The project will claim model or benchmark superiority only when reproducible LeakBench results support it.

## Responsible use

Use only to defend your organisation or authorised clients. Do not exploit or redistribute leaked data. LeakScope is not legal advice and is not a credential verifier. See [SECURITY.md](SECURITY.md) for reporting and operational boundaries.
