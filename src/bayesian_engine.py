"""
Bayesian Network Engine for Attack Prediction
Uses Conditional Probability Tables (CPTs) for each tactic
Calculates P(next_tactic | observed_evidence)
"""
import numpy as np
from typing import Dict, List, Set, Tuple, Optional
from neo4j import GraphDatabase
from pgmpy.models import BayesianNetwork
from pgmpy.factors.discrete import TabularCPD
from pgmpy.inference import VariableElimination
import logging
from config import (
    NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD,
    PRIOR_PROBABILITY, SMOOTHING_FACTOR
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# All MITRE ATT&CK Enterprise Tactics in kill chain order
TACTICS = [
    'reconnaissance',
    'resource-development', 
    'initial-access',
    'execution',
    'persistence',
    'privilege-escalation',
    'defense-evasion',
    'credential-access',
    'discovery',
    'lateral-movement',
    'collection',
    'command-and-control',
    'exfiltration',
    'impact'
]


class BayesianAttackPredictor:
    """
    Bayesian Network for predicting attack progression.
    Each tactic is a node with a CPT based on observed threat group behavior.
    """
    
    def __init__(self):
        self.driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        self.model = None
        self.inference = None
        self.transition_matrix = None
        self.cpds = {}
    
    def close(self):
        self.driver.close()
    
    def build_transition_matrix(self) -> np.ndarray:
        """
        Build transition probability matrix from Neo4j data.
        Matrix[i][j] = P(tactic_j | tactic_i)
        """
        n = len(TACTICS)
        matrix = np.zeros((n, n))
        
        with self.driver.session() as session:
            # Get transition counts from threat group patterns
            result = session.run("""
                MATCH (g:ThreatGroup)-[:USES]->(t1:Technique)-[:BELONGS_TO]->(tac1:Tactic)
                MATCH (g)-[:USES]->(t2:Technique)-[:BELONGS_TO]->(tac2:Tactic)
                WHERE tac1 <> tac2
                WITH tac1.short_name as from_tactic, 
                     tac2.short_name as to_tactic,
                     count(DISTINCT g) as transitions
                RETURN from_tactic, to_tactic, transitions
            """)
            
            for record in result:
                from_tac = record['from_tactic']
                to_tac = record['to_tactic']
                count = record['transitions']
                
                if from_tac in TACTICS and to_tac in TACTICS:
                    i = TACTICS.index(from_tac)
                    j = TACTICS.index(to_tac)
                    matrix[i][j] = count
        
        # Apply Laplace smoothing and normalize
        matrix += SMOOTHING_FACTOR
        row_sums = matrix.sum(axis=1, keepdims=True)
        matrix = matrix / row_sums
        
        self.transition_matrix = matrix
        logger.info("Transition matrix built from threat group data")
        
        return matrix
    
    def build_bayesian_network(self):
        """
        Build a Bayesian Network where:
        - Each tactic is a binary node (observed/not observed)
        - CPT for each tactic conditioned on previous tactics
        """
        logger.info("Building Bayesian Network...")
        
        if self.transition_matrix is None:
            self.build_transition_matrix()
        
        # Create network structure (chain structure following kill chain)
        edges = []
        for i in range(len(TACTICS) - 1):
            edges.append((TACTICS[i], TACTICS[i + 1]))
        
        # Also add skip connections for lateral movement patterns
        skip_connections = [
            ('initial-access', 'execution'),
            ('execution', 'credential-access'),
            ('credential-access', 'lateral-movement'),
            ('discovery', 'collection'),
            ('collection', 'exfiltration'),
            ('command-and-control', 'exfiltration'),
            ('command-and-control', 'impact'),
        ]
        edges.extend(skip_connections)
        
        self.model = BayesianNetwork(edges)
        
        # Create CPDs for each tactic
        for i, tactic in enumerate(TACTICS):
            parents = list(self.model.get_parents(tactic))
            
            if not parents:
                # Root node - use prior probability
                cpd = TabularCPD(
                    variable=tactic,
                    variable_card=2,  # Binary: 0=not observed, 1=observed
                    values=[[1 - PRIOR_PROBABILITY], [PRIOR_PROBABILITY]]
                )
            else:
                # Node with parents - build CPT
                parent_cards = [2] * len(parents)
                num_combinations = 2 ** len(parents)
                
                # Calculate CPT values
                values = np.zeros((2, num_combinations))
                
                for combo_idx in range(num_combinations):
                    # Convert index to parent states
                    parent_states = []
                    temp = combo_idx
                    for _ in parents:
                        parent_states.append(temp % 2)
                        temp //= 2
                    
                    # Calculate P(tactic | parents)
                    if any(parent_states):  # At least one parent observed
                        # Higher probability if earlier tactics observed
                        prob = 0.0
                        for p_idx, p_state in enumerate(parent_states):
                            if p_state == 1:
                                parent_tactic = parents[p_idx]
                                if parent_tactic in TACTICS:
                                    parent_pos = TACTICS.index(parent_tactic)
                                    tactic_pos = TACTICS.index(tactic)
                                    if parent_pos < len(self.transition_matrix) and tactic_pos < len(self.transition_matrix[0]):
                                        prob = max(prob, self.transition_matrix[parent_pos][tactic_pos])
                        
                        values[1][combo_idx] = min(prob * 1.5, 0.95)  # Amplify but cap
                        values[0][combo_idx] = 1 - values[1][combo_idx]
                    else:
                        # No parents observed - low probability
                        values[1][combo_idx] = 0.05
                        values[0][combo_idx] = 0.95
                
                cpd = TabularCPD(
                    variable=tactic,
                    variable_card=2,
                    values=values,
                    evidence=parents,
                    evidence_card=parent_cards
                )
            
            self.cpds[tactic] = cpd
            self.model.add_cpds(cpd)
        
        # Verify model
        if self.model.check_model():
            logger.info("Bayesian Network validated successfully")
        else:
            logger.warning("Bayesian Network validation failed")
        
        # Create inference engine
        self.inference = VariableElimination(self.model)
        
        return self.model
    
    def predict_next_tactics(
        self, 
        observed_tactics: List[str],
        top_k: int = 5
    ) -> List[Tuple[str, float]]:
        """
        Given observed tactics, predict probability of each future tactic.
        Returns list of (tactic, probability) sorted by probability.
        """
        if self.inference is None:
            self.build_bayesian_network()
        
        # Build evidence dictionary
        evidence = {}
        for tactic in TACTICS:
            if tactic in observed_tactics:
                evidence[tactic] = 1
        
        # Query probability of unobserved tactics
        predictions = []
        unobserved = [t for t in TACTICS if t not in observed_tactics]
        
        for tactic in unobserved:
            try:
                result = self.inference.query(
                    variables=[tactic],
                    evidence=evidence
                )
                prob = result.values[1]  # Probability of state=1 (observed)
                predictions.append((tactic, float(prob)))
            except Exception as e:
                logger.warning(f"Could not query {tactic}: {e}")
                # Fallback to transition matrix
                if observed_tactics and self.transition_matrix is not None:
                    last_observed = observed_tactics[-1]
                    if last_observed in TACTICS and tactic in TACTICS:
                        i = TACTICS.index(last_observed)
                        j = TACTICS.index(tactic)
                        predictions.append((tactic, float(self.transition_matrix[i][j])))
        
        # Sort by probability
        predictions.sort(key=lambda x: x[1], reverse=True)
        
        return predictions[:top_k]
    
    def calculate_attack_path_probability(
        self,
        observed_tactics: List[str],
        target_tactic: str
    ) -> Dict:
        """
        Calculate probability of reaching target tactic given observations.
        Also returns most likely path.
        """
        if self.inference is None:
            self.build_bayesian_network()
        
        # Build evidence
        evidence = {t: 1 for t in observed_tactics if t in TACTICS}
        
        # Query target probability
        try:
            result = self.inference.query(
                variables=[target_tactic],
                evidence=evidence
            )
            target_prob = float(result.values[1])
        except:
            target_prob = 0.0
        
        # Find path through intermediate tactics
        observed_positions = [TACTICS.index(t) for t in observed_tactics if t in TACTICS]
        target_pos = TACTICS.index(target_tactic) if target_tactic in TACTICS else -1
        
        if not observed_positions or target_pos < 0:
            return {
                'target_tactic': target_tactic,
                'probability': target_prob,
                'path': [],
                'path_probability': 0.0
            }
        
        # Calculate path probability through likely intermediate tactics
        max_observed = max(observed_positions)
        path = []
        path_prob = 1.0
        
        current_pos = max_observed
        while current_pos < target_pos:
            next_probs = []
            for j in range(current_pos + 1, target_pos + 1):
                next_probs.append((j, self.transition_matrix[current_pos][j]))
            
            if not next_probs:
                break
            
            # Take most likely next step
            best_next = max(next_probs, key=lambda x: x[1])
            path.append(TACTICS[best_next[0]])
            path_prob *= best_next[1]
            current_pos = best_next[0]
        
        return {
            'target_tactic': target_tactic,
            'probability': target_prob,
            'path': path,
            'path_probability': path_prob,
            'observed': observed_tactics
        }
    
    def get_full_risk_assessment(
        self,
        observed_tactics: List[str]
    ) -> Dict:
        """
        Complete risk assessment given observed tactics.
        """
        predictions = self.predict_next_tactics(observed_tactics, top_k=10)
        
        # Calculate impact probability
        impact_analysis = self.calculate_attack_path_probability(
            observed_tactics, 'impact'
        )
        
        exfil_analysis = self.calculate_attack_path_probability(
            observed_tactics, 'exfiltration'
        )
        
        # Risk score calculation
        high_risk_tactics = ['lateral-movement', 'collection', 'exfiltration', 'impact']
        risk_score = 0.0
        for tactic, prob in predictions:
            if tactic in high_risk_tactics:
                weight = 1.5 if tactic in ['exfiltration', 'impact'] else 1.0
                risk_score += prob * weight
        
        risk_score = min(risk_score / 2.0, 1.0)  # Normalize to 0-1
        
        # Determine risk level
        if risk_score >= 0.8:
            risk_level = "CRITICAL"
        elif risk_score >= 0.6:
            risk_level = "HIGH"
        elif risk_score >= 0.4:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        return {
            'observed_tactics': observed_tactics,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'next_tactic_predictions': predictions,
            'impact_probability': impact_analysis['probability'],
            'exfiltration_probability': exfil_analysis['probability'],
            'likely_path_to_impact': impact_analysis['path'],
            'attack_stage': self._determine_attack_stage(observed_tactics)
        }
    
    def _determine_attack_stage(self, observed: List[str]) -> str:
        """Determine current attack stage."""
        if not observed:
            return "No activity"
        
        positions = [TACTICS.index(t) for t in observed if t in TACTICS]
        max_pos = max(positions) if positions else 0
        
        if max_pos >= 12:
            return "Final Stage (Exfil/Impact imminent)"
        elif max_pos >= 9:
            return "Late Stage (Lateral Movement/Collection)"
        elif max_pos >= 6:
            return "Mid Stage (Privilege Escalation/Defense Evasion)"
        elif max_pos >= 3:
            return "Early Stage (Initial Access/Execution)"
        else:
            return "Reconnaissance/Preparation"
    
    def store_cpds_in_neo4j(self):
        """Store CPT values in Neo4j for graph-based queries."""
        logger.info("Storing CPDs in Neo4j...")
        
        if self.transition_matrix is None:
            self.build_transition_matrix()
        
        with self.driver.session() as session:
            for i, from_tactic in enumerate(TACTICS):
                for j, to_tactic in enumerate(TACTICS):
                    prob = float(self.transition_matrix[i][j])
                    
                    session.run("""
                        MATCH (t1:Tactic {short_name: $from_tactic})
                        MATCH (t2:Tactic {short_name: $to_tactic})
                        MERGE (t1)-[r:TRANSITION_TO]->(t2)
                        SET r.probability = $probability,
                            r.log_probability = $log_prob
                    """, {
                        'from_tactic': from_tactic,
                        'to_tactic': to_tactic,
                        'probability': prob,
                        'log_prob': float(np.log(prob + 1e-10))
                    })
        
        logger.info("CPDs stored in Neo4j")


if __name__ == "__main__":
    # Test the Bayesian engine
    predictor = BayesianAttackPredictor()
    
    try:
        # Build network
        predictor.build_bayesian_network()
        
        # Test prediction
        observed = ['initial-access', 'execution']
        print(f"\nObserved tactics: {observed}")
        
        predictions = predictor.predict_next_tactics(observed)
        print("\nPredicted next tactics:")
        for tactic, prob in predictions:
            print(f"  {tactic}: {prob:.2%}")
        
        # Full risk assessment
        assessment = predictor.get_full_risk_assessment(observed)
        print(f"\nRisk Assessment:")
        print(f"  Risk Level: {assessment['risk_level']}")
        print(f"  Risk Score: {assessment['risk_score']:.2%}")
        print(f"  Impact Probability: {assessment['impact_probability']:.2%}")
        print(f"  Attack Stage: {assessment['attack_stage']}")
        
        # Store in Neo4j
        predictor.store_cpds_in_neo4j()
        
    finally:
        predictor.close()