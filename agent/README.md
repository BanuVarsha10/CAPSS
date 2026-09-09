# CAPSS: Context-Aware Adaptive Privacy and Security System

## Overview
CAPSS is an autonomous AI agent framework designed to provide adaptive privacy and security recommendations for 5G/6G User Equipments (UEs). By observing registration data, analyzing security threats, retrieving historical experiences, and consulting a rich knowledge base of cryptographic privacy schemes, CAPSS ensures optimal privacy scheme selection in real-time.

## Architecture
```text
[Context Loader / Systems Loader] -> (RegistrationContext)
       |
       v
[Context Analyzer] <--> [Experience Memory] <--> [RAG Vector Store]
       |                       |                      |
       v                       | (per-UE exact)       | (cross-UE similarity)
(RequirementProfile)           v                      v
       |---------------> [Reasoning Engine] <--> [Scheme Knowledge Base]
                               |
                               v
                        (Recommendation)
                               |
                               v
                       [Policy Generator] -> (PrivacyPolicy) -> [Policy Validator] -> Output
                               |
                               v
                       [Memory Updater] ---> [Experience Memory] & [RAG Vector Store]
```

## Project Structure
```text
capss/
├── agent/              # Legacy embedding agent core + RAG (see Cross-UE RAG section below)
├── context_analyzer/   # Threat/privacy signal analysis -> RequirementProfile (+ ablation modes)
├── context_loader/
├── evaluation/
├── experience_memory/
├── integration/         # Systems -> Privacy -> Agent pipeline wiring (see Integration Layer below)
├── knowledge_base/
├── log_converter/
├── memory_updater/
├── policy_generator/
├── reasoning/           # Scoring/matching engine (see Reasoning Engine Improvements below)
├── schemas/
└── scheme_execution/    # Real cryptographic execution for all 7 privacy schemes (see below)
    └── executors/       # One executor per scheme: ECIES, ML-KEM, DP, AP, GS, IBE, ZKP
```
`tests/` mirrors this with dedicated `tests/scheme_execution/` and `tests/integration/` suites, alongside the original `tests/scenarios/` and per-module tests.

## Scheme Execution Module (`capss/scheme_execution/`)
Real, executable implementations of all 7 privacy schemes the Agent can recommend, plus the framework (`assessment.py`) that validates the Agent's scheme-switching decisions against real measured behavior rather than simulated numbers.

Per-scheme status (see each executor's module docstring for the full cryptographic write-up):
- **ECIES** — real, standards-based: 3GPP TS 33.501 Annex C.4 SUCI concealment (ECDH on NIST P-256 + HKDF-SHA-256 + AES-128-GCM), via the `cryptography` library. The only executor that produces a true SUCI.
- **ML-KEM** — real ML-KEM-768 (FIPS 203) key encapsulation via `liboqs-python`, producing a proposed (not yet 3GPP-standardised) post-quantum SUCI profile. Falls back automatically to a clearly-labeled, size/timing-representative placeholder if `liboqs` isn't installed — never a silent approximation.
- **DP (Dynamic Pseudonym)** — real: HMAC-SHA256 epoch-rotating pseudonym, stdlib-only (`hashlib`/`hmac`/`secrets`).
- **AP (Adaptive Padding)** — real: PADME-inspired traffic-shaping bucket rounding. Carries no identity value at all — fundamentally different from the other six schemes.
- **GS (Group Signature)** — reference-grade: a simplified Schnorr-based ring-signature approximation, not production BBS+ (no pairing library available in this environment).
- **IBE (Identity-Based Encryption)** — reference-grade: identity-keyed hybrid encryption, a documented substitute for full Boneh-Franklin IBE (which needs bilinear pairings, unavailable here).
- **ZKP** — reference-grade but a genuine proof of knowledge, not a stub: Schnorr Σ-protocol identification over NIST P-256.

Every executor's timing is measured via `time.perf_counter()` in the shared base class (`base.py`), and every result carries real byte-level output sizes. `assessment.py` uses this real, measured data to run 4 independent checks — real adaptation occurred, stable under repeated replays, measurably different overhead, and analytically justified for the attack type — before marking a scheme switch "VALIDATED".

Note: `requirements.txt` currently lists only `pydantic`/`pytest`. Exercising the real cryptographic executors also needs `cryptography` (ECIES/ML-KEM/GS/ZKP) and, optionally, `liboqs-python` (ML-KEM's real path only — it degrades gracefully without it).

## Integration Layer (`capss/integration/`)
Wires the Agent to the Systems module's real pipeline:
- **`systems_adapter.py`** — pure field-mapping/translation between Systems' `AttackReport`/`RegistrationRequest` and the Agent's `RegistrationContext`. No reinterpretation of Systems' decisions (an `ALLOW` is never overridden to `TAG`/`BLOCK` here).
- **`full_pipeline.py`** — orchestrates the complete live flow: Systems (`PreAMFValidator` → `ThreatContextGenerator`) → Privacy (`LivePrivacyContext.score()`) → Agent (`CAPSSAgent.process_registration()`).

Design rule enforced in both files: this layer only maps fields and orchestrates calls — it imports and calls Systems'/Privacy's real code, and never modifies it. No detection, scoring, or reasoning logic lives here.

## Reasoning Engine Improvements
This push also fixes three issues in `capss/reasoning/`:
- **EAS cap** (`metrics.py`) — the Experience Alignment Score's influence on the final score is now bounded (±0.15 from neutral) so accumulated history alone can no longer swing a ranking without limit.
- **Attack-type gating for experience retrieval** (`metrics.py`) — both cross-UE (RAG) and a device's own historical experiences now only count as evidence for the CURRENT attack type; a stored experience from an unrelated attack type is excluded rather than discounted.
- **Profile-matcher dampening** (`profile_matcher.py`) — when the knowledge base explicitly documents a scheme as unsuited (`False` affinity) for the current attack type, that scheme's general tracking/correlation-risk fit is dampened so it can no longer override the knowledge base's own attack-type judgment on general properties alone.

## Cross-UE RAG Retrieval Subsystem
CAPSS includes an additive Retrieval-Augmented Generation (RAG) vector search module (`capss.agent.rag`). When a new or cold-start UE (with `< 3` local experiences) registers, CAPSS performs in-memory cosine similarity retrieval across normalized 13-dimensional context vectors from past registrations of other UEs. This enables immediate, evidence-backed privacy recommendations for cold-start UEs before they build their own local interaction history, while preserving 100% exact local history precedence once sufficient per-UE experience exists (`>= 3`).

## Quick Start
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Run the agent against sample paired Systems & Attack datasets:
   ```bash
   python run_agent.py --data data/samples/duplicate_registration_batch.csv --attack-data data/samples/duplicate_registration_attack.csv --schemes data/privacy_schemes.json
   ```

## CLI Usage

```bash
python run_agent.py --data <path> --schemes <path> [options]
```

### Command-Line Arguments:
- `--data <path>` **(Required)**: Path to registration CSV file.
- `--attack-data <path>` **(Optional)**: Path to attack dataset CSV file. *Note: `--attack-data` is required when ingesting raw Systems-module data split across two separate CSVs (registration events and attack detection events) joined on `Request_ID`.*
- `--schemes <path>` **(Required)**: Path to `privacy_schemes.json` knowledge base.
- `--config <path>` **(Optional)**: Path to custom configuration JSON file or directory containing `weights.json` and `thresholds.json`.
- `--experience <path>` **(Optional)**: Path to custom persistent experience store JSON file.
- `--ue <ue_id>` **(Optional)**: Process only registrations matching a specific UE ID.
- `--year <YYYY>` **(Optional)**: Assumed calendar year for timestamps lacking an explicit year (e.g. `--year 2024`).
- `--output <path>` **(Optional)**: Path to write generated policy results to a JSON file.
- `--quiet` **(Optional)**: Suppress verbose per-registration console formatting.
- `--stats` **(Optional)**: Print agent summary and performance statistics after processing.

### Example Commands:
```bash
# Process paired Systems-module batch with output file and stats
python run_agent.py --data data/samples/duplicate_registration_batch.csv --attack-data data/samples/duplicate_registration_attack.csv --schemes data/privacy_schemes.json --output result.json --stats

# Process single standalone registration CSV for a specific UE
python run_agent.py --data data/samples/standard_registrations.csv --schemes data/privacy_schemes.json --ue UE-001
```

## Interactive Demonstration
Run the 3-step user registration adaptation scenario (Normal → Privacy Issue → Linkability & Hybrid Scheme):
```bash
python scripts/test_user_flow.py
```

Run the full, narrated Systems → Privacy → Agent pipeline demo (no arguments; uses an isolated in-memory experience store and subscriber allow-list, and modifies no files):
```bash
python demo_for_mentor.py
```

## Testing
The Agent-scope test suite (`agent/tests/`) currently has **241 passing tests**, covering context loading, threat analysis, experience memory FIFO eviction, reasoning engine scoring (including the EAS cap and attack-type gating fixes above), policy validation, 5 full traffic scenarios, the Scheme Execution Module (`tests/scheme_execution/`), and the Systems/Agent integration layer (`tests/integration/`). This count is specific to the Agent scope on this branch, not the full combined-project test count.

Run the full test suite:
```bash
python -m pytest tests/ -v
```

Run only scenario tests:
```bash
python -m pytest tests/scenarios/ -v
```

Run only the scheme execution / integration tests added in this push:
```bash
python -m pytest tests/scheme_execution/ tests/integration/ -v
```

## Extension Guide
To extend CAPSS with new privacy schemes or reasoning logic, update `data/privacy_schemes.json` or customize module classes in `capss/agent/capss_agent.py`.
