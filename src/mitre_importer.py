"""
Complete MITRE ATT&CK Importer
Downloads and imports ALL tactics, techniques, groups, malware, tools
Creates vector embeddings for semantic search
"""
import json
import requests
import logging
from typing import Dict, List, Any, Optional
from neo4j import GraphDatabase
from tqdm import tqdm
from config import (
    NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD,
    MITRE_ENTERPRISE_URL, EMBEDDING_DIMENSION
)
from embedding_service import get_embedding_service

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MITREImporter:
    """Import complete MITRE ATT&CK data into Neo4j with embeddings."""
    
    def __init__(self):
        self.driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        self.embedding_service = get_embedding_service()
        self.stix_data = None
        
    def close(self):
        self.driver.close()
    
    def download_mitre_data(self) -> Dict:
        """Download MITRE ATT&CK STIX data."""
        logger.info("Downloading MITRE ATT&CK Enterprise data...")
        response = requests.get(MITRE_ENTERPRISE_URL)
        response.raise_for_status()
        self.stix_data = response.json()
        logger.info(f"Downloaded {len(self.stix_data['objects'])} STIX objects")
        return self.stix_data
    
    def setup_database(self):
        """Create indexes and constraints."""
        with self.driver.session() as session:
            # Constraints
            constraints = [
                "CREATE CONSTRAINT IF NOT EXISTS FOR (t:Tactic) REQUIRE t.id IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (t:Technique) REQUIRE t.id IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (g:ThreatGroup) REQUIRE g.id IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (m:Malware) REQUIRE m.id IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (t:Tool) REQUIRE t.id IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (m:Mitigation) REQUIRE m.id IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (d:DataSource) REQUIRE d.id IS UNIQUE",
                "CREATE CONSTRAINT IF NOT EXISTS FOR (c:Campaign) REQUIRE c.id IS UNIQUE",
            ]
            for constraint in constraints:
                session.run(constraint)
            
            # Vector index for semantic search
            session.run(f"""
                CREATE VECTOR INDEX technique_embeddings IF NOT EXISTS
                FOR (t:Technique)
                ON t.embedding
                OPTIONS {{
                    indexConfig: {{
                        `vector.dimensions`: {EMBEDDING_DIMENSION},
                        `vector.similarity_function`: 'cosine'
                    }}
                }}
            """)
            
            # Full-text indexes
            session.run("""
                CREATE FULLTEXT INDEX technique_search IF NOT EXISTS
                FOR (t:Technique)
                ON EACH [t.name, t.description]
            """)
            
            logger.info("Database indexes and constraints created")
    
    def parse_stix_objects(self) -> Dict[str, List[Dict]]:
        """Parse STIX objects into categories."""
        categories = {
            'tactics': [],
            'techniques': [],
            'groups': [],
            'malware': [],
            'tools': [],
            'mitigations': [],
            'data_sources': [],
            'campaigns': [],
            'relationships': []
        }
        
        for obj in self.stix_data['objects']:
            obj_type = obj.get('type', '')
            
            if obj_type == 'x-mitre-tactic':
                categories['tactics'].append(obj)
            elif obj_type == 'attack-pattern':
                categories['techniques'].append(obj)
            elif obj_type == 'intrusion-set':
                categories['groups'].append(obj)
            elif obj_type == 'malware':
                categories['malware'].append(obj)
            elif obj_type == 'tool':
                categories['tools'].append(obj)
            elif obj_type == 'course-of-action':
                categories['mitigations'].append(obj)
            elif obj_type == 'x-mitre-data-source':
                categories['data_sources'].append(obj)
            elif obj_type == 'campaign':
                categories['campaigns'].append(obj)
            elif obj_type == 'relationship':
                categories['relationships'].append(obj)
        
        for cat, items in categories.items():
            logger.info(f"Found {len(items)} {cat}")
        
        return categories
    
    def get_mitre_id(self, obj: Dict) -> Optional[str]:
        """Extract MITRE ID (e.g., T1566) from external references."""
        for ref in obj.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                return ref.get('external_id')
        return None
    
    def import_tactics(self, tactics: List[Dict]):
        """Import all tactics."""
        logger.info("Importing tactics...")
        with self.driver.session() as session:
            for tactic in tqdm(tactics, desc="Tactics"):
                if tactic.get('revoked') or tactic.get('x_mitre_deprecated'):
                    continue
                    
                mitre_id = self.get_mitre_id(tactic)
                short_name = tactic.get('x_mitre_shortname', '')
                
                session.run("""
                    MERGE (t:Tactic {id: $id})
                    SET t.stix_id = $stix_id,
                        t.name = $name,
                        t.description = $description,
                        t.short_name = $short_name,
                        t.url = $url,
                        t.order = $order
                """, {
                    'id': mitre_id,
                    'stix_id': tactic['id'],
                    'name': tactic.get('name', ''),
                    'description': tactic.get('description', ''),
                    'short_name': short_name,
                    'url': f"https://attack.mitre.org/tactics/{mitre_id}/",
                    'order': self._get_tactic_order(short_name)
                })
    
    def _get_tactic_order(self, short_name: str) -> int:
        """Get kill chain order for tactics."""
        order_map = {
            'reconnaissance': 1,
            'resource-development': 2,
            'initial-access': 3,
            'execution': 4,
            'persistence': 5,
            'privilege-escalation': 6,
            'defense-evasion': 7,
            'credential-access': 8,
            'discovery': 9,
            'lateral-movement': 10,
            'collection': 11,
            'command-and-control': 12,
            'exfiltration': 13,
            'impact': 14
        }
        return order_map.get(short_name, 99)
    
    def import_techniques(self, techniques: List[Dict]):
        """Import all techniques with embeddings."""
        logger.info("Importing techniques with embeddings...")
        
        # Filter valid techniques
        valid_techniques = [
            t for t in techniques 
            if not t.get('revoked') and not t.get('x_mitre_deprecated')
        ]
        
        # Generate embeddings for all techniques
        logger.info("Generating embeddings for techniques...")
        descriptions = []
        for tech in valid_techniques:
            desc = f"{tech.get('name', '')}. {tech.get('description', '')[:500]}"
            descriptions.append(desc)
        
        embeddings = self.embedding_service.embed_batch(descriptions)
        
        # Import to Neo4j
        with self.driver.session() as session:
            for i, tech in enumerate(tqdm(valid_techniques, desc="Techniques")):
                mitre_id = self.get_mitre_id(tech)
                
                # Get tactics this technique belongs to
                tactics = []
                for phase in tech.get('kill_chain_phases', []):
                    if phase.get('kill_chain_name') == 'mitre-attack':
                        tactics.append(phase.get('phase_name'))
                
                # Check if sub-technique
                is_subtechnique = '.' in (mitre_id or '')
                parent_id = mitre_id.split('.')[0] if is_subtechnique else None
                
                # Get platforms
                platforms = tech.get('x_mitre_platforms', [])
                
                # Get detection info
                detection = tech.get('x_mitre_detection', '')
                
                session.run("""
                    MERGE (t:Technique {id: $id})
                    SET t.stix_id = $stix_id,
                        t.name = $name,
                        t.description = $description,
                        t.detection = $detection,
                        t.platforms = $platforms,
                        t.is_subtechnique = $is_subtechnique,
                        t.parent_id = $parent_id,
                        t.url = $url,
                        t.embedding = $embedding
                """, {
                    'id': mitre_id,
                    'stix_id': tech['id'],
                    'name': tech.get('name', ''),
                    'description': tech.get('description', ''),
                    'detection': detection,
                    'platforms': platforms,
                    'is_subtechnique': is_subtechnique,
                    'parent_id': parent_id,
                    'url': f"https://attack.mitre.org/techniques/{mitre_id}/",
                    'embedding': embeddings[i]
                })
                
                # Link to tactics
                for tactic in tactics:
                    session.run("""
                        MATCH (tech:Technique {id: $tech_id})
                        MATCH (tac:Tactic {short_name: $tactic_name})
                        MERGE (tech)-[:BELONGS_TO]->(tac)
                    """, {'tech_id': mitre_id, 'tactic_name': tactic})
                
                # Link sub-techniques to parent
                if is_subtechnique and parent_id:
                    session.run("""
                        MATCH (sub:Technique {id: $sub_id})
                        MATCH (parent:Technique {id: $parent_id})
                        MERGE (sub)-[:SUBTECHNIQUE_OF]->(parent)
                    """, {'sub_id': mitre_id, 'parent_id': parent_id})
    
    def import_groups(self, groups: List[Dict]):
        """Import threat groups."""
        logger.info("Importing threat groups...")
        with self.driver.session() as session:
            for group in tqdm(groups, desc="Groups"):
                if group.get('revoked') or group.get('x_mitre_deprecated'):
                    continue
                
                mitre_id = self.get_mitre_id(group)
                aliases = group.get('aliases', [])
                
                session.run("""
                    MERGE (g:ThreatGroup {id: $id})
                    SET g.stix_id = $stix_id,
                        g.name = $name,
                        g.description = $description,
                        g.aliases = $aliases,
                        g.url = $url
                """, {
                    'id': mitre_id,
                    'stix_id': group['id'],
                    'name': group.get('name', ''),
                    'description': group.get('description', ''),
                    'aliases': aliases,
                    'url': f"https://attack.mitre.org/groups/{mitre_id}/"
                })
    
    def import_malware(self, malware_list: List[Dict]):
        """Import malware."""
        logger.info("Importing malware...")
        with self.driver.session() as session:
            for malware in tqdm(malware_list, desc="Malware"):
                if malware.get('revoked') or malware.get('x_mitre_deprecated'):
                    continue
                
                mitre_id = self.get_mitre_id(malware)
                
                session.run("""
                    MERGE (m:Malware {id: $id})
                    SET m.stix_id = $stix_id,
                        m.name = $name,
                        m.description = $description,
                        m.platforms = $platforms,
                        m.url = $url
                """, {
                    'id': mitre_id,
                    'stix_id': malware['id'],
                    'name': malware.get('name', ''),
                    'description': malware.get('description', ''),
                    'platforms': malware.get('x_mitre_platforms', []),
                    'url': f"https://attack.mitre.org/software/{mitre_id}/"
                })
    
    def import_tools(self, tools: List[Dict]):
        """Import tools."""
        logger.info("Importing tools...")
        with self.driver.session() as session:
            for tool in tqdm(tools, desc="Tools"):
                if tool.get('revoked') or tool.get('x_mitre_deprecated'):
                    continue
                
                mitre_id = self.get_mitre_id(tool)
                
                session.run("""
                    MERGE (t:Tool {id: $id})
                    SET t.stix_id = $stix_id,
                        t.name = $name,
                        t.description = $description,
                        t.platforms = $platforms,
                        t.url = $url
                """, {
                    'id': mitre_id,
                    'stix_id': tool['id'],
                    'name': tool.get('name', ''),
                    'description': tool.get('description', ''),
                    'platforms': tool.get('x_mitre_platforms', []),
                    'url': f"https://attack.mitre.org/software/{mitre_id}/"
                })
    
    def import_mitigations(self, mitigations: List[Dict]):
        """Import mitigations."""
        logger.info("Importing mitigations...")
        with self.driver.session() as session:
            for mitigation in tqdm(mitigations, desc="Mitigations"):
                if mitigation.get('revoked') or mitigation.get('x_mitre_deprecated'):
                    continue
                
                mitre_id = self.get_mitre_id(mitigation)
                
                session.run("""
                    MERGE (m:Mitigation {id: $id})
                    SET m.stix_id = $stix_id,
                        m.name = $name,
                        m.description = $description,
                        m.url = $url
                """, {
                    'id': mitre_id,
                    'stix_id': mitigation['id'],
                    'name': mitigation.get('name', ''),
                    'description': mitigation.get('description', ''),
                    'url': f"https://attack.mitre.org/mitigations/{mitre_id}/"
                })
    
    def import_relationships(self, relationships: List[Dict]):
        """Import all relationships."""
        logger.info("Importing relationships...")
        
        # Build STIX ID to MITRE ID mapping
        id_map = {}
        for obj in self.stix_data['objects']:
            mitre_id = self.get_mitre_id(obj)
            if mitre_id:
                id_map[obj['id']] = mitre_id
        
        with self.driver.session() as session:
            for rel in tqdm(relationships, desc="Relationships"):
                if rel.get('revoked'):
                    continue
                
                source_id = id_map.get(rel.get('source_ref'))
                target_id = id_map.get(rel.get('target_ref'))
                rel_type = rel.get('relationship_type', '')
                
                if not source_id or not target_id:
                    continue
                
                # Map relationship types to Neo4j relationships
                if rel_type == 'uses':
                    # Group/Malware/Tool uses Technique
                    session.run("""
                        MATCH (source) WHERE source.id = $source_id
                        MATCH (target) WHERE target.id = $target_id
                        MERGE (source)-[:USES]->(target)
                    """, {'source_id': source_id, 'target_id': target_id})
                
                elif rel_type == 'mitigates':
                    session.run("""
                        MATCH (m:Mitigation {id: $source_id})
                        MATCH (t:Technique {id: $target_id})
                        MERGE (m)-[:MITIGATES]->(t)
                    """, {'source_id': source_id, 'target_id': target_id})
                
                elif rel_type == 'attributed-to':
                    session.run("""
                        MATCH (c:Campaign {id: $source_id})
                        MATCH (g:ThreatGroup {id: $target_id})
                        MERGE (c)-[:ATTRIBUTED_TO]->(g)
                    """, {'source_id': source_id, 'target_id': target_id})
    
    def calculate_tactic_transitions(self):
        """Calculate transition probabilities between tactics based on threat group patterns."""
        logger.info("Calculating tactic transition probabilities...")
        
        with self.driver.session() as session:
            # Find tactics used together by groups and count transitions
            result = session.run("""
                MATCH (g:ThreatGroup)-[:USES]->(t1:Technique)-[:BELONGS_TO]->(tac1:Tactic)
                MATCH (g)-[:USES]->(t2:Technique)-[:BELONGS_TO]->(tac2:Tactic)
                WHERE tac1.order < tac2.order
                WITH tac1, tac2, count(DISTINCT g) as group_count
                RETURN tac1.short_name as from_tactic, 
                       tac2.short_name as to_tactic,
                       group_count
                ORDER BY from_tactic, group_count DESC
            """)
            
            transitions = {}
            for record in result:
                from_tac = record['from_tactic']
                to_tac = record['to_tactic']
                count = record['group_count']
                
                if from_tac not in transitions:
                    transitions[from_tac] = {}
                transitions[from_tac][to_tac] = count
            
            # Normalize to probabilities and store
            for from_tac, to_tacs in transitions.items():
                total = sum(to_tacs.values())
                for to_tac, count in to_tacs.items():
                    probability = count / total
                    
                    session.run("""
                        MATCH (t1:Tactic {short_name: $from_tactic})
                        MATCH (t2:Tactic {short_name: $to_tactic})
                        MERGE (t1)-[r:LEADS_TO]->(t2)
                        SET r.probability = $probability,
                            r.observation_count = $count
                    """, {
                        'from_tactic': from_tac,
                        'to_tactic': to_tac,
                        'probability': probability,
                        'count': count
                    })
            
            logger.info("Transition probabilities calculated and stored")
    
    def run_full_import(self):
        """Run the complete import process."""
        logger.info("Starting full MITRE ATT&CK import...")
        
        # Download data
        self.download_mitre_data()
        
        # Setup database
        self.setup_database()
        
        # Parse objects
        categories = self.parse_stix_objects()
        
        # Import all categories
        self.import_tactics(categories['tactics'])
        self.import_techniques(categories['techniques'])
        self.import_groups(categories['groups'])
        self.import_malware(categories['malware'])
        self.import_tools(categories['tools'])
        self.import_mitigations(categories['mitigations'])
        self.import_relationships(categories['relationships'])
        
        # Calculate transitions
        self.calculate_tactic_transitions()
        
        logger.info("Import complete!")
        
        # Print summary
        with self.driver.session() as session:
            result = session.run("""
                MATCH (n)
                RETURN labels(n)[0] as label, count(*) as count
                ORDER BY count DESC
            """)
            print("\n=== Import Summary ===")
            for record in result:
                print(f"{record['label']}: {record['count']}")


if __name__ == "__main__":
    importer = MITREImporter()
    try:
        importer.run_full_import()
    finally:
        importer.close()