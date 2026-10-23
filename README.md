# Checkpoint: `mcp-workflow-adapter`

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

Production-grade, domain-neutral Model Context Protocol (MCP) workflow durability and orchestration library.

> **Core Systems Thesis:** Remembering a conversation is not the same as knowing the authoritative state of a business process.

Conversational interfaces excel at natural language understanding and clarification. However, multi-step professional procedures require authoritative backend execution state: knowing which checklist steps actually committed before a network drop, which numeric readings passed server-side bounds validation, whether a retried tool call already executed, whether another operator is using the physical instrument, and what domain escalation policies govern out-of-range exceptions.

`mcp-workflow-adapter` provides a pure hexagonal core that decouples conversational agents from stateful business process durability.

---

## Key Capabilities

* **Domain-Neutral Hexagonal Ports:** Zero domain strings or hardcoded schemas in core contracts (`DomainPolicyPort`, `StorageBackendPort`, `OrchestratorPort`, `NotificationPort`).
* **Zero AWS SDK Leakage in Core:** Core modules (`models.py`, `errors.py`, `ports.py`, `state_machine.py`, `idempotency.py`, `redaction.py`, `auth.py`, `well_known.py`, `mcp_server.py`, `backends/local.py`) contain zero `boto3` or `botocore` imports. AWS dependencies are strictly confined to optional `backends/aws_*.py` plugins.
* **4-State Business State Machine:** Strictly limited to `CREATED`, `RUNNING`, `BLOCKED`, and `COMPLETED`. Transient database, network, or orchestration failures never mark a business workflow failed—they preserve committed state and raise retryable `BACKEND_UNAVAILABLE` errors.
* **Atomic Idempotency & Replay Envelopes:** Canonical JSON SHA-256 payload hashing with atomic ledger commits. Replays return stored results with `duplicate: True`; payload mismatches trigger `IDEMPOTENCY_CONFLICT`.
* **Multi-Session Disambiguation & Active Asset Locks:** Start mutations atomically acquire physical asset locks (`ASSET#<asset_id>`). Ambiguous status queries across multiple active workflows prompt structured voice disambiguation instead of guessing.
* **Transactional Notification Engine:** Writes notifications atomically to an outbox within the same transaction as state mutations, dispataching via sinks without blocking workflow commits.
* **Streamable HTTP Transport & Headerless `401`:** Streamable HTTP ASGI server (`POST /mcp`) implementing the Alexa+ headerless `401` authentication contract with RFC 9728 protected resource discovery.
* **Local & Cloud Storage Backends:**
  * `LocalBackend`: File-backed SQLite in WAL mode (`PRAGMA journal_mode=WAL`, `BEGIN IMMEDIATE` transactions).
  * `AWSBackend`: Single-table DynamoDB (`TransactWriteItems`) + Fenced AWS Step Functions Reconciler (`R1`–`R8`).

---

## 5-Minute Quick Start (Local Offline Mode)

```bash
# 1. Install in editable development mode
pip install -e ".[dev]"

# 2. Run the offline test suite
pytest tests/unit tests/contract

# 3. Execute the secondary domain example (Industrial Pump Inspection)
python examples/industrial_pump_inspection.py
```

---

## Core Architecture

```text
               +----------------------------------------+
               |  Conversational Client (Alexa+ / LLM)  |
               +----------------------------------------+
                                   |
                         HTTP POST /mcp (Streamable)
                                   v
               +----------------------------------------+
               |       Streamable HTTP MCP Server       |
               | (auth.py, well_known.py, mcp_server.py)|
               +----------------------------------------+
                                   |
                                   v
             +---------------------------------------------+
             |         Hexagonal Ports & Contracts         |
             |       (DomainPolicyPort, StoragePort)       |
             +---------------------------------------------+
               /                                         \
              v                                           v
+-------------------------------+       +------------------------------------+
|         LocalBackend          |       |             AWSBackend             |
|   (SQLite WAL + Local Sink)   |       | (DynamoDB TransactWriteItems + SFN)|
+-------------------------------+       +------------------------------------+
```

---

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
