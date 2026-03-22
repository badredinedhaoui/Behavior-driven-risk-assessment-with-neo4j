#!/usr/bin/env python3
"""
Complete Setup Script for MITRE ATT&CK Knowledge Graph
Run this after starting Neo4j to set up everything.
"""
import subprocess
import sys
import time
import logging
from pathlib import Path

# Add the src directory to Python path
project_dir = Path(__file__).parent
src_dir = project_dir / 'src'
sys.path.insert(0, str(src_dir))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def check_neo4j_connection():
    """Check if Neo4j is available."""
    from neo4j import GraphDatabase
    from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD
    
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        with driver.session() as session:
            session.run("RETURN 1")
        driver.close()
        return True
    except Exception as e:
        logger.error(f"Neo4j connection failed: {e}")
        return False


def wait_for_neo4j(max_attempts=30):
    """Wait for Neo4j to be ready."""
    logger.info("Waiting for Neo4j to be ready...")
    
    for attempt in range(max_attempts):
        if check_neo4j_connection():
            logger.info("Neo4j is ready!")
            return True
        
        logger.info(f"Attempt {attempt + 1}/{max_attempts} - Neo4j not ready, waiting...")
        time.sleep(2)
    
    logger.error("Neo4j failed to start in time")
    return False


def run_import():
    """Run the MITRE ATT&CK import."""
    logger.info("Starting MITRE ATT&CK import...")
    
    from mitre_importer import MITREImporter
    
    importer = MITREImporter()
    try:
        importer.run_full_import()
        logger.info("Import completed successfully!")
    finally:
        importer.close()


def build_bayesian_network():
    """Build and store Bayesian network."""
    logger.info("Building Bayesian network...")
    
    from bayesian_engine import BayesianAttackPredictor
    
    predictor = BayesianAttackPredictor()
    try:
        predictor.build_bayesian_network()
        predictor.store_cpds_in_neo4j()
        logger.info("Bayesian network built and stored!")
    finally:
        predictor.close()


def test_system():
    """Run a quick test of the system."""
    logger.info("Testing the system...")
    
    from hybrid_retriever import HybridRetriever
    
    retriever = HybridRetriever()
    try:
        # Test hybrid search
        results = retriever.hybrid_search(
            "PowerShell encoded command execution",
            observed_tactics=['initial-access']
        )
        
        logger.info(f"Hybrid search returned {len(results)} results")
        
        if results:
            top = results[0]
            logger.info(f"Top result: [{top.technique_id}] {top.technique_name}")
            logger.info(f"Hybrid score: {top.hybrid_score:.3f}")
        
        # Test risk assessment
        assessment = retriever.bayesian_predictor.get_full_risk_assessment(
            ['initial-access', 'execution']
        )
        logger.info(f"Risk assessment: {assessment['risk_level']} ({assessment['risk_score']:.2%})")
        
        logger.info("All tests passed!")
        
    finally:
        retriever.close()


def main():
    """Main setup process."""
    print("=" * 60)
    print("MITRE ATT&CK Knowledge Graph - Setup")
    print("=" * 60)
    
    # Step 1: Wait for Neo4j
    if not wait_for_neo4j():
        print("\nERROR: Could not connect to Neo4j.")
        print("Make sure Neo4j is running: docker-compose up -d")
        sys.exit(1)
    
    # Step 2: Import MITRE ATT&CK
    run_import()
    
    # Step 3: Build Bayesian network
    build_bayesian_network()
    
    # Step 4: Test the system
    test_system()
    
    print("\n" + "=" * 60)
    print("SETUP COMPLETE!")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Start the API server: python src/api/main.py")
    print("2. Process logs: python src/log_processor.py")
    print("3. Open Neo4j Browser: http://localhost:7474")
    print("\nAPI will be available at: http://localhost:8000")
    print("API docs at: http://localhost:8000/docs")


if __name__ == "__main__":
    main()