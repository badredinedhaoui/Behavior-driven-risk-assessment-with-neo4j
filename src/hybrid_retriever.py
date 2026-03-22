"""
Hybrid Retrieval System
Combines: Vector Embeddings + Graph Traversal + Bayesian Inference
"""
import numpy as np
from typing import Dict, List, Any, Optional, Tuple
from neo4j import GraphDatabase
from dataclasses import dataclass
import logging
from config import (
    NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD,
    VECTOR_WEIGHT, GRAPH_WEIGHT, BAYESIAN_WEIGHT,
    EMBEDDING_DIMENSION
)
from embedding_service import get_embedding_service
from bayesian_engine import BayesianAttackPredictor, TACTICS

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class RetrievalResult:
    """Result from hybrid retrieval."""
    technique_id: str
    technique_name: str
    description: str
    tactics: List[str]
    vector_score: float
    graph_score: float
    bayesian_score: float
    hybrid_score: float
    related_groups: List[str]
    mitigations: List[str]


class HybridRetriever:
    """
    Hybrid retrieval combining:
    1. Vector similarity search (semantic matching)
    2. Graph traversal (relationship-based expansion)
    3. Bayesian inference (probabilistic relevance)
    """
    
    def __init__(self):
        self.driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        self.embedding_service = get_embedding_service()
        self.bayesian_predictor = BayesianAttackPredictor()
    
    def close(self):
        self.driver.close()
        self.bayesian_predictor.close()
    
    def vector_search(
        self, 
        query: str, 
        top_k: int = 10
    ) -> List[Dict]:
        """
        Search techniques using vector similarity.
        Uses Neo4j's native vector index.
        """
        # Generate query embedding
        query_embedding = self.embedding_service.embed_text(query)
        
        with self.driver.session() as session:
            result = session.run("""
                CALL db.index.vector.queryNodes(
                    'technique_embeddings',
                    $top_k,
                    $embedding
                )
                YIELD node, score
                MATCH (node)-[:BELONGS_TO]->(tac:Tactic)
                OPTIONAL MATCH (g:ThreatGroup)-[:USES]->(node)
                OPTIONAL MATCH (m:Mitigation)-[:MITIGATES]->(node)
                RETURN node.id as id,
                       node.name as name,
                       node.description as description,
                       collect(DISTINCT tac.short_name) as tactics,
                       collect(DISTINCT g.name)[..5] as groups,
                       collect(DISTINCT m.name)[..5] as mitigations,
                       score as vector_score
                ORDER BY score DESC
            """, {
                'embedding': query_embedding,
                'top_k': top_k
            })
            
            return [dict(record) for record in result]
    
    def graph_expand(
        self, 
        technique_ids: List[str],
        max_hops: int = 2
    ) -> List[Dict]:
        """
        Expand from initial techniques using graph traversal.
        Finds related techniques through shared tactics, groups, tools.
        """
        with self.driver.session() as session:
            result = session.run("""
                UNWIND $technique_ids as tech_id
                MATCH (start:Technique {id: tech_id})
                
                // Find related through shared tactics
                OPTIONAL MATCH (start)-[:BELONGS_TO]->(tac:Tactic)<-[:BELONGS_TO]-(related1:Technique)
                WHERE related1.id <> start.id
                
                // Find related through shared threat groups
                OPTIONAL MATCH (g:ThreatGroup)-[:USES]->(start)
                OPTIONAL MATCH (g)-[:USES]->(related2:Technique)
                WHERE related2.id <> start.id
                
                // Find related through sub-techniques
                OPTIONAL MATCH (start)-[:SUBTECHNIQUE_OF]->(parent:Technique)
                OPTIONAL MATCH (parent)<-[:SUBTECHNIQUE_OF]-(sibling:Technique)
                WHERE sibling.id <> start.id
                
                WITH start, 
                     collect(DISTINCT related1) + collect(DISTINCT related2) + collect(DISTINCT sibling) as related_nodes
                
                UNWIND related_nodes as related
                MATCH (related)-[:BELONGS_TO]->(tac:Tactic)
                
                // Calculate graph relevance score
                OPTIONAL MATCH path = shortestPath((start)-[*..3]-(related))
                
                RETURN DISTINCT related.id as id,
                       related.name as name,
                       related.description as description,
                       collect(DISTINCT tac.short_name) as tactics,
                       CASE WHEN path IS NOT NULL 
                            THEN 1.0 / length(path) 
                            ELSE 0.1 END as graph_score
                ORDER BY graph_score DESC
                LIMIT 20
            """, {'technique_ids': technique_ids})
            
            return [dict(record) for record in result]
    
    def calculate_bayesian_relevance(
        self,
        techniques: List[Dict],
        observed_tactics: List[str]
    ) -> List[Dict]:
        """
        Calculate Bayesian relevance for each technique.
        Based on P(technique's tactics | observed tactics).
        """
        # Build Bayesian network if not ready
        if self.bayesian_predictor.inference is None:
            self.bayesian_predictor.build_bayesian_network()
        
        # Get predictions for unobserved tactics
        predictions = dict(self.bayesian_predictor.predict_next_tactics(observed_tactics, top_k=14))
        
        # Score each technique based on its tactics
        for tech in techniques:
            tech_tactics = tech.get('tactics', [])
            
            # Calculate average predicted probability for technique's tactics
            bayesian_scores = []
            for tactic in tech_tactics:
                if tactic in predictions:
                    bayesian_scores.append(predictions[tactic])
                elif tactic in observed_tactics:
                    bayesian_scores.append(1.0)  # Already observed
                else:
                    bayesian_scores.append(0.1)  # Default low score
            
            tech['bayesian_score'] = np.mean(bayesian_scores) if bayesian_scores else 0.1
        
        return techniques
    
    def hybrid_search(
        self,
        query: str,
        observed_tactics: Optional[List[str]] = None,
        top_k: int = 10
    ) -> List[RetrievalResult]:
        """
        Full hybrid search combining all three approaches.
        
        Args:
            query: Natural language query (log message, IOC, description)
            observed_tactics: Already detected tactics for Bayesian context
            top_k: Number of results to return
        
        Returns:
            List of RetrievalResult with combined scores
        """
        observed_tactics = observed_tactics or []
        
        # Step 1: Vector search
        logger.info("Performing vector search...")
        vector_results = self.vector_search(query, top_k=top_k * 2)
        
        # Step 2: Graph expansion
        logger.info("Expanding via graph traversal...")
        initial_ids = [r['id'] for r in vector_results[:5]]
        graph_results = self.graph_expand(initial_ids)
        
        # Step 3: Merge results
        all_results = {}
        
        for r in vector_results:
            all_results[r['id']] = {
                'id': r['id'],
                'name': r['name'],
                'description': r['description'],
                'tactics': r['tactics'],
                'vector_score': r['vector_score'],
                'graph_score': 0.0,
                'groups': r.get('groups', []),
                'mitigations': r.get('mitigations', [])
            }
        
        for r in graph_results:
            if r['id'] in all_results:
                all_results[r['id']]['graph_score'] = r['graph_score']
            else:
                all_results[r['id']] = {
                    'id': r['id'],
                    'name': r['name'],
                    'description': r['description'],
                    'tactics': r['tactics'],
                    'vector_score': 0.0,
                    'graph_score': r['graph_score'],
                    'groups': [],
                    'mitigations': []
                }
        
        # Step 4: Calculate Bayesian scores
        logger.info("Calculating Bayesian relevance...")
        results_list = list(all_results.values())
        results_list = self.calculate_bayesian_relevance(results_list, observed_tactics)
        
        # Step 5: Calculate hybrid score
        for r in results_list:
            r['hybrid_score'] = (
                VECTOR_WEIGHT * r['vector_score'] +
                GRAPH_WEIGHT * r['graph_score'] +
                BAYESIAN_WEIGHT * r.get('bayesian_score', 0.1)
            )
        
        # Sort by hybrid score
        results_list.sort(key=lambda x: x['hybrid_score'], reverse=True)
        
        # Convert to RetrievalResult objects
        final_results = []
        for r in results_list[:top_k]:
            final_results.append(RetrievalResult(
                technique_id=r['id'],
                technique_name=r['name'],
                description=r['description'][:300] + "..." if len(r['description']) > 300 else r['description'],
                tactics=r['tactics'],
                vector_score=r['vector_score'],
                graph_score=r['graph_score'],
                bayesian_score=r.get('bayesian_score', 0.0),
                hybrid_score=r['hybrid_score'],
                related_groups=r.get('groups', []),
                mitigations=r.get('mitigations', [])
            ))
        
        return final_results
    
    def analyze_log_entry(
        self,
        log_message: str,
        previous_detections: Optional[List[str]] = None
    ) -> Dict:
        """
        Analyze a single log entry using hybrid retrieval.
        Returns matched techniques and risk assessment.
        """
        previous_detections = previous_detections or []
        
        # Extract tactics from previous detections
        observed_tactics = []
        with self.driver.session() as session:
            if previous_detections:
                result = session.run("""
                    UNWIND $tech_ids as tech_id
                    MATCH (t:Technique {id: tech_id})-[:BELONGS_TO]->(tac:Tactic)
                    RETURN DISTINCT tac.short_name as tactic
                """, {'tech_ids': previous_detections})
                observed_tactics = [r['tactic'] for r in result]
        
        # Perform hybrid search
        matches = self.hybrid_search(log_message, observed_tactics, top_k=5)
        
        if not matches:
            return {
                'log_message': log_message,
                'matches': [],
                'risk_assessment': None
            }
        
        # Get all tactics from matches
        all_tactics = set(observed_tactics)
        for match in matches:
            all_tactics.update(match.tactics)
        
        # Get risk assessment
        risk_assessment = self.bayesian_predictor.get_full_risk_assessment(list(all_tactics))
        
        return {
            'log_message': log_message[:200],
            'matches': [
                {
                    'technique_id': m.technique_id,
                    'technique_name': m.technique_name,
                    'tactics': m.tactics,
                    'hybrid_score': m.hybrid_score,
                    'vector_score': m.vector_score,
                    'graph_score': m.graph_score,
                    'bayesian_score': m.bayesian_score,
                    'mitigations': m.mitigations
                }
                for m in matches
            ],
            'observed_tactics': list(all_tactics),
            'risk_assessment': risk_assessment
        }
    
    def batch_analyze_logs(
        self,
        log_messages: List[str]
    ) -> Dict:
        """
        Analyze multiple log entries with cumulative context.
        """
        all_detections = []
        all_tactics = set()
        results = []
        
        for log in log_messages:
            analysis = self.analyze_log_entry(log, all_detections)
            results.append(analysis)
            
            # Accumulate detections
            for match in analysis['matches']:
                if match['hybrid_score'] > 0.5:  # Confidence threshold
                    all_detections.append(match['technique_id'])
                    all_tactics.update(match['tactics'])
        
        # Final risk assessment with all context
        final_risk = self.bayesian_predictor.get_full_risk_assessment(list(all_tactics))
        
        return {
            'individual_results': results,
            'total_logs_analyzed': len(log_messages),
            'unique_techniques_detected': list(set(all_detections)),
            'unique_tactics_detected': list(all_tactics),
            'final_risk_assessment': final_risk
        }


if __name__ == "__main__":
    # Test hybrid retriever
    retriever = HybridRetriever()
    
    try:
        # Test single query
        print("Testing hybrid search...")
        results = retriever.hybrid_search(
            "PowerShell executing encoded base64 command from suspicious process",
            observed_tactics=['initial-access']
        )
        
        print(f"\nFound {len(results)} results:\n")
        for r in results[:5]:
            print(f"[{r.technique_id}] {r.technique_name}")
            print(f"  Tactics: {', '.join(r.tactics)}")
            print(f"  Hybrid Score: {r.hybrid_score:.3f}")
            print(f"    Vector: {r.vector_score:.3f}, Graph: {r.graph_score:.3f}, Bayesian: {r.bayesian_score:.3f}")
            print()
        
        # Test log analysis
        print("\nTesting log analysis...")
        analysis = retriever.analyze_log_entry(
            "User account created followed by privilege escalation to SYSTEM"
        )
        
        print(f"Risk Level: {analysis['risk_assessment']['risk_level']}")
        print(f"Risk Score: {analysis['risk_assessment']['risk_score']:.2%}")
        
    finally:
        retriever.close()