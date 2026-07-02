CAPSS Project Tasks and Team Responsibilities
Project Title

Context-Aware Privacy Protection and Scheme Selection (CAPSS) for SUCI in 5G Networks

Project Objective

Develop a 3GPP-compliant framework that:

Compares multiple subscriber identity protection schemes from literature.
Studies metadata leakage and correlation risks.
Implements privacy-preserving registration logging.
Performs metadata minimization.
Collects network and system performance metrics.
Uses retrieval-augmented LLM reasoning over historical registration experiences.
Dynamically recommends privacy mechanisms for future registration cycles.
Maintains compatibility with Open5GS and UERANSIM.

The framework does not modify the current 5G authentication flow. Instead, decisions are generated from previous registration experiences and applied to future registrations.

High-Level Architecture
Previous Registrations
        |
        v
Metadata Analysis
        |
        v
Metadata Minimization
        |
        v
Experience Database
(FAISS / ChromaDB)
        |
        v
Top-K Retrieval
        |
        v
LLM Reasoning Engine
        |
        v
Policy Generation
        |
        v
Scheme Selection
(ECIES / PQC / Padding / Others)
        |
        v
SUCI Generation
        |
        v
Registration Request
        |
        v
Open5GS Core
(AMF -> AUSF -> UDM)
        |
        v
Logging & Metrics Collection
        |
        +----> Future Registration Cycles
Team Structure
Member 1: Systems and Networking
Owns
open5gs/
ueransim/
experiments/
results/
Responsibilities
Open5GS installation and configuration.
UERANSIM setup.
Subscriber registration management.
Scheme integration.
Authentication latency measurements.
CPU and memory measurements.
Congestion measurements.
Running all experiments.
Maintaining deployment scripts.
Producing experimental results and benchmarks.
Files and Folders
open5gs/configs/
open5gs/scripts/

ueransim/configs/
ueransim/scripts/

experiments/
Branch
systems
Member 2: Privacy and Metadata
Owns
logging/
privacy/
datasets/
Responsibilities
Registration logging.
Parsing AMF and Open5GS logs.
Metadata extraction.
Metadata minimization.
Correlation analysis.
Privacy score framework.
Dataset generation.
Literature review.
Documentation of privacy schemes.
Validation of metadata leakage metrics.
Files and Folders
logging/
logging/schemas/

privacy/
privacy/schemes/

datasets/
Branch
privacy
Member 3: AI and RAG
Owns
agent/
Responsibilities
Experience database design.
FAISS or Chroma integration.
Embedding generation.
Retrieval mechanisms.
LLM reasoning engine.
Prompt engineering.
Policy generation.
Explainability mechanisms.
Retrieval benchmarking.
Recommendation generation.
Files and Folders
agent/rag/
agent/llm/
agent/examples/
Branch
ai-agent
Infrastructure Tasks
Systems Team
Complete Open5GS deployment.
Complete UERANSIM deployment.
Configure UE and gNB.
Add subscribers.
Validate PDU session establishment.
Configure restart scripts.
Configure deployment scripts.
Build experiment execution scripts.
Privacy Team
Create metadata inventory.
Identify correlation risks.
Define privacy metrics.
Define metadata minimization strategies.
Design registration schemas.
Create processed datasets.
AI Team
Design experience schema.
Implement vector storage.
Implement retrieval mechanisms.
Design prompts.
Build policy generators.
Connect retrieval with LLM reasoning.
Logging Tasks
Registration Logger

Capture:

Timestamp
IMSI/SUPI
Selected scheme
Authentication status
Cell ID
Registration latency
Session identifiers
Mobility information
Metrics Collector

Capture:

CPU utilization
Memory utilization
Authentication latency
Registration throughput
Congestion indicators
Output Files
datasets/raw/registrations.csv
datasets/raw/metrics.csv
Metadata Tasks
Metadata Inventory

Document:

Timestamp information
Cell identifiers
Mobility traces
Registration frequencies
Session durations
Authentication outcomes
Scheme identifiers
Correlation Analysis

Study:

Temporal correlations
Mobility correlations
Cross-session linkability
Subscriber fingerprinting risks
Length-based attacks
Logging privacy risks
Metadata Minimization

Implement:

Time bucketing
Cell aggregation
Location zoning
Identifier anonymization
Privacy-preserving logs
Reduced precision storage
Outputs
datasets/processed/minimized_metadata.csv
Privacy Score Framework

Metrics:

Entropy score
Linkability score
Correlation risk
Metadata leakage score
Logging exposure score
Final Output
Privacy Score: 0–100
AI and RAG Tasks
Experience Schema

Each experience contains:

Battery level
CPU utilization
Memory utilization
Congestion level
Authentication latency
Scheme selected
Privacy score
Roaming status
Signal quality
Retrieval Pipeline
Current Context
        |
        v
Top-K Similar Experiences
        |
        v
LLM Reasoning
        |
        v
Policy Recommendation

The LLM does not make decisions without context.

It reasons over retrieved historical experiences.

This ensures:

Explainability.
Lower hallucination risk.
Reproducibility.
Academic defensibility.
Policy Generation Tasks
Inputs
Historical registrations.
Metadata analysis.
Privacy scores.
CPU utilization.
Authentication latency.
Congestion levels.
User context.
Device context.
Roaming status.
Outputs
Recommended privacy scheme.
Explanation.
Expected overhead.
Expected privacy improvement.
Candidate Schemes
ECIES
ML-KEM
Padding-based approaches
Additional schemes from literature
Experimental Tasks
Experiment Categories
Single UE experiments.
Multiple UE experiments.
Congestion scenarios.
High-latency scenarios.
High-load scenarios.
Roaming simulations.
Performance Metrics
Authentication latency.
CPU utilization.
Memory consumption.
Registration throughput.
Congestion levels.
Privacy Metrics
Privacy score.
Correlation score.
Metadata leakage.
Linkability.
AI Metrics
Retrieval latency.
LLM reasoning time.
Recommendation quality.
Explanation quality.
Paper Responsibilities
Systems Team

Write:

System Architecture
Implementation
Experimental Setup
Benchmark Results
Privacy Team

Write:

Related Work
Metadata Analysis
Privacy Metrics
Minimization Framework
AI Team

Write:

RAG Architecture
Experience Database
LLM Reasoning Framework
Explainability Mechanisms
Collaboration Rules
Development Branches
main
systems
privacy
ai-agent
Rules
No direct commits to main.
Merge after integration meetings.
Pull before starting work.
Resolve conflicts collaboratively.
Maintain documentation continuously.
Keep datasets and logs outside version control.
Update architecture documents whenever components change.
Repository Ownership
open5gs/          -> Systems Team
ueransim/         -> Systems Team
experiments/      -> Systems Team
results/          -> Systems Team

logging/          -> Privacy Team
privacy/          -> Privacy Team
datasets/         -> Privacy Team

agent/            -> AI Team

docs/             -> Shared
paper/            -> Shared
presentation/     -> Shared

