# FROST Threshold Signature Service (TrustGuard Treasury)

A production-grade, asynchronous **FastAPI microservice** implementing the **FROST (Flexible Round-Optimized Schnorr Threshold Signatures)** protocol for $t$-of-$n$ threshold signing schemes with BIP-340 Schnorr signatures over the `secp256k1` elliptic curve.

---

## Key Features

- **FROST Multi-Party Computation Protocol**: Implements two-round threshold Schnorr signatures based on the 2020 paper by Komlo & Goldberg.
- **BIP-340 Compliance**: Cryptographic engine powered by `coincurve` (wrapping `libsecp256k1`) ensuring standard Bitcoin-style Schnorr signatures.
- **Finite Field & Lagrange Operations**: Modular polynomial arithmetic and Lagrange interpolation for partial signature weight calculation.
- **Preprocessing & Nonce Caching**: TTL-based cache for pre-computed nonce commitments $(D_i, E_i)$ to ensure low-latency signing in high-throughput environments.
- **Intelligent Subset Routing**: Signer selection algorithm prioritizing active and healthy council members.
- **Concurrency & Rate Limiting**: Built-in concurrency guards (max 3 concurrent signing sessions) and IP-based rate limiting via `slowapi`.
- **Complete REST API**: Endpoints for approval requests, async status polling, metrics/health, and independent signature verification.

---

## Project Structure

```
FROST_Signature_Service/
├── pyproject.toml              # Project dependencies and build specification
├── uv.lock                     # UV dependency lockfile
├── run.py                      # Server runner entrypoint
└── src/
    ├── main.py                 # FastAPI application definition and lifecycle
    ├── config.py               # Environment configuration and parameter tuning
    ├── api/
    │   ├── error_handlers.py   # Global exception handlers and error contracts
    │   ├── exceptions.py       # Custom HTTP and domain exceptions
    │   └── routes/
    │       ├── approvals.py    # POST /approvals/request, GET /approvals/status/{id}
    │       ├── health.py       # GET /health and GET /metrics endpoints
    │       ├── signing.py      # Backwards-compatible legacy route aliases
    │       └── verify.py       # POST /approvals/verify for cryptographic verification
    ├── crypto/
    │   ├── lagrange.py         # Lagrange interpolation coefficient calculations
    │   ├── schnorr.py          # Secp256k1 point multiplication, addition, BIP-340 hashing
    │   └── utils.py            # Field math, byte serializations, epoch helpers
    ├── models/
    │   ├── message.py          # Input payload model & SHA-256 digesting
    │   ├── nonce.py            # Nonce scalar and point commitment models
    │   ├── request.py          # Pydantic request and response schemas
    │   ├── session.py          # Signing session state machine models
    │   ├── signature.py        # Aggregate (R, s) signature schema
    │   └── signer.py           # Council member key share representation
    └── services/
        ├── concurrency.py      # Semaphore-based session concurrency control
        ├── frost.py            # Core FROST protocol engine (Round 1, Round 2, Aggregation)
        ├── key_manager.py      # Key share distribution and joint public key validation
        ├── nonce_cache.py      # TTL-based nonce commitment caching service
        ├── rate_limit.py       # SlowAPI limiter instance
        └── subset_selector.py  # Signer subset routing and bias logic
```

---

## Installation & Setup

### 1. Prerequisites
- Python 3.11 or 3.12
- C compiler tools for `libsecp256k1` / `coincurve`

### 2. Install Dependencies
Using `uv` (recommended):
```bash
uv sync
```
Or using standard `pip`:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r <(pip list) # or install directly:
pip install "fastapi>=0.115.0" "uvicorn[standard]>=0.32.0" "coincurve>=20.0.0" "pydantic>=2.9.0" "cachetools>=5.5.0" "slowapi>=0.1.9" "structlog>=24.4.0" "python-dotenv>=1.0.1" "numpy>=2.3.3"
```

### 3. Run the Service
```bash
python3 run.py
```
Or via uvicorn directly:
```bash
uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/approvals/request` | Submit a message for $t$-of-$n$ threshold signing |
| `GET` | `/approvals/status/{id}` | Check status and retrieve aggregated signature $(R, s)$ |
| `POST` | `/approvals/verify` | Verify an aggregate signature against the joint public key |
| `GET` | `/health` | Service health status and signer availability |
| `GET` | `/metrics` | Prometheus/service operational metrics |

Interactive OpenAPI documentation is available at `http://localhost:8000/docs`.
