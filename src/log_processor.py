"""
Security Log Processor
Processes logs from various sources and maps to MITRE techniques
"""
import json
import re
import logging
import sys
from typing import Dict, List, Any, Optional, Generator
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
from neo4j import GraphDatabase

# Add project root to path to find config.py
current_file = Path(__file__).resolve()
project_root = current_file.parent.parent
sys.path.insert(0, str(project_root))

from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, LOGS_DIR
from hybrid_retriever import HybridRetriever

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class LogEntry:
    """Normalized log entry."""
    timestamp: str
    source: str
    message: str
    raw: Dict[str, Any]
    event_type: Optional[str] = None
    severity: Optional[str] = None
    host: Optional[str] = None
    user: Optional[str] = None


@dataclass
class Detection:
    """A detected technique from log analysis."""
    log_entry: LogEntry
    technique_id: str
    technique_name: str
    tactics: List[str]
    confidence: float
    vector_score: float
    graph_score: float
    bayesian_score: float


class LogParser:
    """Parse various log formats into normalized entries."""
    
    @staticmethod
    def parse_json_log(log_data: Dict) -> LogEntry:
        """Parse JSON-formatted log."""
        return LogEntry(
            timestamp=log_data.get('timestamp', log_data.get('@timestamp', '')),
            source=log_data.get('source', log_data.get('log_source', 'unknown')),
            message=log_data.get('message', log_data.get('msg', str(log_data))),
            raw=log_data,
            event_type=log_data.get('event_type', log_data.get('eventType')),
            severity=log_data.get('severity', log_data.get('level')),
            host=log_data.get('host', log_data.get('hostname')),
            user=log_data.get('user', log_data.get('username'))
        )
    
    @staticmethod
    def parse_syslog(line: str) -> LogEntry:
        """Parse syslog format."""
        # Example: Jan 1 00:00:00 hostname process[pid]: message
        pattern = r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s*(.*)$'
        match = re.match(pattern, line)
        
        if match:
            return LogEntry(
                timestamp=match.group(1),
                source=match.group(3),
                message=match.group(4),
                raw={'line': line},
                host=match.group(2)
            )
        
        return LogEntry(
            timestamp='',
            source='syslog',
            message=line,
            raw={'line': line}
        )
    
    @staticmethod
    def parse_windows_event(event: Dict) -> LogEntry:
        """Parse Windows Event Log."""
        return LogEntry(
            timestamp=event.get('TimeCreated', {}).get('@SystemTime', ''),
            source=event.get('Provider', {}).get('@Name', 'Windows'),
            message=event.get('EventData', {}).get('Data', str(event)),
            raw=event,
            event_type=str(event.get('EventID', '')),
            host=event.get('Computer', ''),
            user=event.get('Security', {}).get('@UserID', '')
        )
    
    @staticmethod
    def parse_cef(line: str) -> LogEntry:
        """Parse CEF (Common Event Format)."""
        # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        parts = line.split('|')
        
        if len(parts) >= 7:
            return LogEntry(
                timestamp='',
                source=f"{parts[1]}_{parts[2]}",
                message=parts[5],
                raw={'line': line, 'extension': parts[6] if len(parts) > 6 else ''},
                event_type=parts[4],
                severity=parts[6] if len(parts) > 6 else None
            )
        
        return LogEntry(
            timestamp='',
            source='cef',
            message=line,
            raw={'line': line}
        )


class SecurityLogProcessor:
    """
    Main processor for security logs.
    Reads logs, analyzes with hybrid retrieval, stores detections.
    """
    
    def __init__(self):
        self.driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        self.retriever = HybridRetriever()
        self.parser = LogParser()
        self.detections: List[Detection] = []
    
    def close(self):
        self.driver.close()
        self.retriever.close()
    
    def read_log_file(
        self, 
        file_path: Path,
        log_format: str = 'json'
    ) -> Generator[LogEntry, None, None]:
        """Read and parse a log file."""
        
        with open(file_path, 'r') as f:
            if log_format == 'json':
                # Try JSON lines format
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            data = json.loads(line)
                            yield self.parser.parse_json_log(data)
                        except json.JSONDecodeError:
                            continue
            
            elif log_format == 'json_array':
                # Full JSON array
                data = json.load(f)
                for entry in data:
                    yield self.parser.parse_json_log(entry)
            
            elif log_format == 'syslog':
                for line in f:
                    yield self.parser.parse_syslog(line.strip())
            
            elif log_format == 'cef':
                for line in f:
                    if line.strip().startswith('CEF:'):
                        yield self.parser.parse_cef(line.strip())
    
    def process_log_entry(
        self,
        entry: LogEntry,
        previous_tactics: List[str]
    ) -> List[Detection]:
        """Process a single log entry."""
        
        # Analyze with hybrid retrieval
        analysis = self.retriever.analyze_log_entry(
            entry.message,
            previous_detections=[]  # Will be populated from previous_tactics
        )
        
        detections = []
        for match in analysis['matches']:
            if match['hybrid_score'] >= 0.3:  # Confidence threshold
                detection = Detection(
                    log_entry=entry,
                    technique_id=match['technique_id'],
                    technique_name=match['technique_name'],
                    tactics=match['tactics'],
                    confidence=match['hybrid_score'],
                    vector_score=match['vector_score'],
                    graph_score=match['graph_score'],
                    bayesian_score=match['bayesian_score']
                )
                detections.append(detection)
        
        return detections
    
    def process_log_file(
        self,
        file_path: Path,
        log_format: str = 'json'
    ) -> Dict:
        """Process an entire log file."""
        
        logger.info(f"Processing log file: {file_path}")
        
        all_detections = []
        all_tactics = set()
        log_count = 0
        
        for entry in self.read_log_file(file_path, log_format):
            log_count += 1
            
            detections = self.process_log_entry(entry, list(all_tactics))
            all_detections.extend(detections)
            
            for d in detections:
                all_tactics.update(d.tactics)
            
            if log_count % 100 == 0:
                logger.info(f"Processed {log_count} logs, {len(all_detections)} detections")
        
        self.detections = all_detections
        
        # Final risk assessment
        risk_assessment = self.retriever.bayesian_predictor.get_full_risk_assessment(
            list(all_tactics)
        )
        
        return {
            'file': str(file_path),
            'total_logs': log_count,
            'total_detections': len(all_detections),
            'unique_techniques': list(set(d.technique_id for d in all_detections)),
            'unique_tactics': list(all_tactics),
            'risk_assessment': risk_assessment,
            'detections': [
                {
                    'technique_id': d.technique_id,
                    'technique_name': d.technique_name,
                    'tactics': d.tactics,
                    'confidence': d.confidence,
                    'timestamp': d.log_entry.timestamp,
                    'message': d.log_entry.message[:200]
                }
                for d in all_detections[:100]  # Limit for display
            ]
        }
    
    def store_detections_in_neo4j(self, session_id: str):
        """Store detections in Neo4j for historical analysis."""
        
        logger.info(f"Storing {len(self.detections)} detections in Neo4j...")
        
        with self.driver.session() as session:
            # Create detection session
            session.run("""
                CREATE (s:DetectionSession {
                    id: $session_id,
                    timestamp: datetime(),
                    detection_count: $count
                })
            """, {
                'session_id': session_id,
                'count': len(self.detections)
            })
            
            # Store each detection
            for detection in self.detections:
                session.run("""
                    MATCH (s:DetectionSession {id: $session_id})
                    MATCH (t:Technique {id: $technique_id})
                    CREATE (d:Detection {
                        timestamp: $timestamp,
                        log_message: $message,
                        confidence: $confidence,
                        source: $source
                    })
                    CREATE (d)-[:DETECTED_TECHNIQUE]->(t)
                    CREATE (d)-[:PART_OF]->(s)
                """, {
                    'session_id': session_id,
                    'technique_id': detection.technique_id,
                    'timestamp': detection.log_entry.timestamp,
                    'message': detection.log_entry.message[:500],
                    'confidence': detection.confidence,
                    'source': detection.log_entry.source
                })
        
        logger.info("Detections stored successfully")
    
    def generate_report(self) -> str:
        """Generate a text report of detections."""
        
        if not self.detections:
            return "No detections to report."
        
        # Get risk assessment
        all_tactics = set()
        for d in self.detections:
            all_tactics.update(d.tactics)
        
        risk = self.retriever.bayesian_predictor.get_full_risk_assessment(list(all_tactics))
        
        report = []
        report.append("=" * 60)
        report.append("SECURITY LOG ANALYSIS REPORT")
        report.append("=" * 60)
        report.append(f"\nGenerated: {datetime.now().isoformat()}")
        report.append(f"Total Detections: {len(self.detections)}")
        report.append(f"Unique Techniques: {len(set(d.technique_id for d in self.detections))}")
        report.append(f"Unique Tactics: {len(all_tactics)}")
        
        report.append(f"\n{'=' * 60}")
        report.append("RISK ASSESSMENT")
        report.append(f"{'=' * 60}")
        report.append(f"Risk Level: {risk['risk_level']}")
        report.append(f"Risk Score: {risk['risk_score']:.2%}")
        report.append(f"Attack Stage: {risk['attack_stage']}")
        report.append(f"Impact Probability: {risk['impact_probability']:.2%}")
        report.append(f"Exfiltration Probability: {risk['exfiltration_probability']:.2%}")
        
        report.append(f"\n{'=' * 60}")
        report.append("PREDICTED NEXT TACTICS")
        report.append(f"{'=' * 60}")
        for tactic, prob in risk['next_tactic_predictions'][:5]:
            report.append(f"  {tactic}: {prob:.2%}")
        
        report.append(f"\n{'=' * 60}")
        report.append("TOP DETECTIONS BY CONFIDENCE")
        report.append(f"{'=' * 60}")
        
        sorted_detections = sorted(self.detections, key=lambda x: x.confidence, reverse=True)
        for d in sorted_detections[:10]:
            report.append(f"\n[{d.technique_id}] {d.technique_name}")
            report.append(f"  Confidence: {d.confidence:.2%}")
            report.append(f"  Tactics: {', '.join(d.tactics)}")
            report.append(f"  Log: {d.log_entry.message[:100]}...")
        
        return "\n".join(report)


if __name__ == "__main__":
    # Example usage
    processor = SecurityLogProcessor()
    
    try:
        # Create sample log file for testing
        sample_logs = [
            {"timestamp": "2024-01-15T10:30:00Z", "source": "endpoint", "message": "PowerShell.exe spawned from WINWORD.EXE with encoded command"},
            {"timestamp": "2024-01-15T10:31:00Z", "source": "endpoint", "message": "New scheduled task created: UpdateCheck"},
            {"timestamp": "2024-01-15T10:32:00Z", "source": "auth", "message": "Failed login attempt for admin from 192.168.1.100"},
            {"timestamp": "2024-01-15T10:33:00Z", "source": "network", "message": "DNS query to suspicious domain: malware.evil.com"},
            {"timestamp": "2024-01-15T10:34:00Z", "source": "endpoint", "message": "LSASS memory access by unknown process"},
        ]
        
        # Write sample log file
        sample_file = LOGS_DIR / "sample_logs.json"
        with open(sample_file, 'w') as f:
            for log in sample_logs:
                f.write(json.dumps(log) + "\n")
        
        # Process the file
        result = processor.process_log_file(sample_file, log_format='json')
        
        # Print report
        print(processor.generate_report())
        
        # Store in Neo4j
        processor.store_detections_in_neo4j(f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        
    finally:
        processor.close()