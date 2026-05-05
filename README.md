# MITRE ATT&CK Threat Intelligence System

A local threat detection system that analyzes security logs, maps them to real-world attacker techniques from the MITRE ATT&CK framework, and predicts where an attack might be heading next.

---

## The idea

Most security tools flag individual events. This project tries to answer a harder question: given a sequence of suspicious activity, what is the attacker likely doing next?

To do that, I built a pipeline that combines three signals — semantic search, graph relationships, and Bayesian probability — to score and rank MITRE ATT&CK techniques against incoming log data, then uses those matches to estimate attack progression and risk.

---

## How it works

1. **Log parsing** — ingests logs from common formats (JSON, syslog, Windows Event, CEF) and normalizes them
2. **Technique matching** — runs a hybrid search across a Neo4j knowledge graph to find the most relevant MITRE techniques for each log entry
3. **Risk prediction** — a Bayesian network trained on real threat group behavior estimates which tactics are likely to appear next and how close the attack is to impact or exfiltration

The knowledge graph is populated from the official MITRE ATT&CK STIX dataset and includes techniques, threat groups, malware, tools, mitigations, and the relationships between them.

---

## Stack

- **Neo4j** — stores the ATT&CK knowledge graph and runs vector + graph queries
- **sentence-transformers** — generates local embeddings for semantic log matching (no external APIs)
- **pgmpy** — Bayesian network for attack stage prediction
- **FastAPI** — REST API for log analysis and risk assessment
- **Docker** — Neo4j runs in a container, everything else is local Python

---

## Current state

The core pipeline works end to end:

- Full MITRE ATT&CK import (techniques, groups, malware, mitigations, relationships)
- Hybrid retrieval combining vector similarity + graph traversal + Bayesian scoring
- REST API with endpoints for single log analysis, batch processing, and risk assessment
- Detection sessions stored back in Neo4j for historical queries

---

## What's next

A few things I want to add:

- **SIGMA rule integration** — map existing detection rules to ATT&CK techniques automatically so the system can consume rules from the community
- **Dashboard UI** — a simple frontend to visualize attack progression on the kill chain and browse detections
- **Streaming ingestion** — replace the file-based log processor with a Kafka consumer for real-time analysis
- **Feedback loop** — let analysts confirm or reject detections and use that signal to retrain the Bayesian priors over time
- **Coverage reports** — given a set of SIGMA rules or log sources, show which ATT&CK tactics and techniques are blind spots

---

## Running it locally

```bash
# Start Neo4j
docker-compose up -d

# Install dependencies
pip install -r requirements.txt

# Import ATT&CK data and build the Bayesian model
python run_setup.py

# Start the API
python src/api/main.py
```

API runs at `http://localhost:8000` — Swagger docs at `/docs`.
