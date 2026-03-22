"""
Configuration for the MITRE ATT&CK Knowledge Graph System
All settings for local deployment
"""
import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
LOGS_DIR = BASE_DIR / "logs"

# Create directories
for dir_path in [DATA_DIR, MODELS_DIR, LOGS_DIR]:
    dir_path.mkdir(exist_ok=True)

# Neo4j Configuration
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "mitreattack123")

# Embedding Model (Local - no API needed)
EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
EMBEDDING_DIMENSION = 384  # all-MiniLM-L6-v2 outputs 384 dimensions

# MITRE ATT&CK Data Sources
MITRE_ENTERPRISE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
MITRE_ICS_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json"
MITRE_MOBILE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json"

# Bayesian Network Settings
PRIOR_PROBABILITY = 0.1  # Default prior for unobserved tactics
SMOOTHING_FACTOR = 0.01  # Laplace smoothing for CPTs

# Hybrid Retrieval Weights
VECTOR_WEIGHT = 0.4
GRAPH_WEIGHT = 0.3
BAYESIAN_WEIGHT = 0.3

# Risk Thresholds
RISK_THRESHOLDS = {
    "critical": 0.8,
    "high": 0.6,
    "medium": 0.4,
    "low": 0.2
}

# Logging
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"