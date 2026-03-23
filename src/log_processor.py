"""
Security Log Processor
Processes logs from various sources and maps to MITRE techniques
"""
import json
import re
import logging
import sys
import argparse
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


# ---------------------------------------------------------------------------
# Windows Security Event ID enrichment map
# Maps EventID -> (human description, [relevant MITRE tactic hints])
# Used to build a semantically rich message for the retriever instead of
# dumping raw field names/SIDs which the vector model cannot interpret well.
# ---------------------------------------------------------------------------
WINDOWS_EVENT_DESCRIPTIONS = {
    # --- Account Logon / Logon Events ---
    "4624": ("Successful logon to the system", ["initial-access", "lateral-movement"]),
    "4625": ("Failed logon attempt, possible brute force or credential stuffing", ["credential-access"]),
    "4634": ("Account logoff", []),
    "4647": ("User initiated logoff", []),
    "4648": ("Logon attempted using explicit credentials, possible pass-the-hash or lateral movement", ["lateral-movement", "credential-access"]),
    "4649": ("Replay attack detected", ["credential-access"]),
    "4672": ("Special privileges assigned to new logon, possible privilege escalation", ["privilege-escalation"]),
    "4675": ("SIDs filtered during logon", []),
    "4768": ("Kerberos TGT request, possible Kerberoasting or AS-REP roasting", ["credential-access"]),
    "4769": ("Kerberos service ticket request, possible Kerberoasting", ["credential-access"]),
    "4771": ("Kerberos pre-authentication failed, possible password spray", ["credential-access"]),
    "4776": ("Domain controller attempted to validate credentials, possible pass-the-hash", ["credential-access"]),
    "4778": ("Remote desktop or terminal session reconnected", ["lateral-movement"]),
    "4779": ("Remote desktop or terminal session disconnected", []),

    # --- Account Management ---
    "4720": ("New user account created", ["persistence"]),
    "4722": ("User account enabled", ["persistence"]),
    "4723": ("User attempted to change account password", ["credential-access"]),
    "4724": ("Password reset attempted on a user account", ["credential-access"]),
    "4725": ("User account disabled", ["defense-evasion"]),
    "4726": ("User account deleted", ["defense-evasion"]),
    "4728": ("User added to a privileged global security group", ["privilege-escalation", "persistence"]),
    "4729": ("User removed from a privileged global security group", []),
    "4732": ("User added to a privileged local security group", ["privilege-escalation", "persistence"]),
    "4733": ("User removed from a privileged local security group", []),
    "4738": ("User account changed", ["persistence"]),
    "4740": ("User account locked out, possible brute force attack", ["credential-access"]),
    "4756": ("User added to a privileged universal security group", ["privilege-escalation", "persistence"]),
    "4767": ("User account unlocked", []),
    "4794": ("Attempt to set Directory Services Restore Mode administrator password, possible domain persistence or credential manipulation", ["credential-access", "persistence", "privilege-escalation"]),
    "4798": ("User local group membership enumerated, possible discovery activity", ["discovery"]),
    "4799": ("Security-enabled local group membership enumerated, possible discovery activity", ["discovery"]),

    # --- Process & Execution ---
    "4688": ("New process created", ["execution"]),
    "4689": ("Process exited", []),
    "4696": ("Primary token assigned to process", ["privilege-escalation"]),

    # --- Scheduled Tasks ---
    "4698": ("Scheduled task created, possible persistence mechanism", ["persistence", "execution"]),
    "4699": ("Scheduled task deleted", ["defense-evasion"]),
    "4700": ("Scheduled task enabled", ["persistence"]),
    "4701": ("Scheduled task disabled", ["defense-evasion"]),
    "4702": ("Scheduled task updated", ["persistence"]),

    # --- Audit / Policy Changes ---
    "4715": ("Audit policy on object changed", ["defense-evasion"]),
    "4719": ("System audit policy changed, possible defense evasion", ["defense-evasion"]),
    "4739": ("Domain policy changed", ["defense-evasion", "persistence"]),
    "4817": ("Auditing settings on object changed", ["defense-evasion"]),
    "4906": ("CrashOnAuditFail value changed, possible audit evasion", ["defense-evasion"]),
    "4907": ("Auditing settings on object changed", ["defense-evasion"]),
    "4912": ("Per-user audit policy changed", ["defense-evasion"]),

    # --- Object Access ---
    "4656": ("Handle to object requested", ["collection"]),
    "4657": ("Registry value modified, possible persistence or defense evasion", ["persistence", "defense-evasion"]),
    "4663": ("Attempt to access an object", ["collection"]),
    "4670": ("Permissions on object changed", ["defense-evasion"]),

    # --- Logon / Session Special Cases ---
    "4964": ("Special groups assigned to new logon", ["privilege-escalation"]),

    # --- Service Control ---
    "7045": ("New service installed on the system, possible persistence", ["persistence", "execution"]),
    "7034": ("Service crashed unexpectedly", []),
    "7036": ("Service changed state", []),
    "7040": ("Service start type changed", ["persistence", "defense-evasion"]),

    # --- Windows Defender / Security ---
    "1102": ("Audit log cleared, possible log tampering or defense evasion", ["defense-evasion"]),
    "1100": ("Event logging service shut down", ["defense-evasion"]),
    "4616": ("System time changed, possible timestomping", ["defense-evasion"]),

    # --- Network / Firewall ---
    "5140": ("Network share accessed", ["lateral-movement", "collection"]),
    "5145": ("Network share object access checked", ["lateral-movement", "discovery"]),
    "5156": ("Windows Filtering Platform permitted a connection", []),
    "5157": ("Windows Filtering Platform blocked a connection", []),
    "5158": ("Windows Filtering Platform permitted a bind to local port", []),

    # --- PowerShell / Script Block ---
    "4103": ("PowerShell module logging, possible script execution", ["execution"]),
    "4104": ("PowerShell script block logged, possible encoded or obfuscated command execution", ["execution", "defense-evasion"]),

    # --- Active Directory ---
    "4662": ("Operation performed on Active Directory object", ["discovery", "collection"]),
    "4742": ("Computer account changed", ["persistence"]),
    "4743": ("Computer account deleted", []),
    "4741": ("Computer account created", ["persistence"]),
    "4781": ("Account name changed", ["defense-evasion"]),
    "4782": ("Password hash accessed, possible credential dumping", ["credential-access"]),
    "4793": ("Password policy API called", ["credential-access"]),

    # --- Misc Sensitive Privilege Use ---
    "4673": ("Sensitive privilege used", ["privilege-escalation"]),
    "4674": ("Operation attempted on a privileged object", ["privilege-escalation"]),
    "4985": ("Transaction state changed", []),
}


def build_enriched_message(
    event_id: str,
    data_fields: Dict[str, str],
    computer: str,
    user: str
) -> str:
    """
    Build a semantically rich message for the hybrid retriever.

    Instead of: "EventID=4794 SubjectUserSid=S-1-5-21-..."
    Produces:   "Attempt to set Directory Services Restore Mode administrator
                 password on 2016dc.hqcorp.local by administrator in domain HQCORP.
                 Possible domain persistence or credential manipulation."
    """
    description, tactic_hints = WINDOWS_EVENT_DESCRIPTIONS.get(
        event_id, (f"Windows Security Event {event_id}", [])
    )

    parts = [description]

    # Skip values that are SIDs, GUIDs, hex codes, or empty placeholders
    skip_patterns = re.compile(
        r'^(S-1-|{[0-9a-fA-F\-]+}|0x[0-9a-fA-F]+|%%\d+|-$)'
    )

    # Ordered list of fields we want to surface with readable labels
    field_labels = {
        "SubjectUserName":   "by user",
        "SubjectDomainName": "in domain",
        "TargetUserName":    "targeting user",
        "TargetDomainName":  "in target domain",
        "ProcessName":       "via process",
        "CommandLine":       "with command",
        "ParentProcessName": "spawned from",
        "ServiceName":       "service name",
        "ServiceFileName":   "service binary",
        "ObjectName":        "on object",
        "ShareName":         "share",
        "TaskName":          "task",
        "Workstation":       "from workstation",
        "IpAddress":         "from IP",
        "LogonType":         "logon type",
        "PrivilegeList":     "privileges",
        "Status":            "status",
    }

    for field, label in field_labels.items():
        value = data_fields.get(field, "").strip()
        if value and not skip_patterns.match(value) and value.lower() not in ("n/a", "-", ""):
            parts.append(f"{label} {value}")

    if computer:
        parts.append(f"on host {computer}")

    if tactic_hints:
        parts.append(f"Relevant attack phases: {', '.join(tactic_hints)}")

    return ". ".join(parts)


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
        return LogEntry(timestamp='', source='syslog', message=line, raw={'line': line})

    @staticmethod
    def parse_windows_event(event: Dict) -> LogEntry:
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
        return LogEntry(timestamp='', source='cef', message=line, raw={'line': line})

    @staticmethod
    def parse_evtx_record(record) -> Optional[LogEntry]:
        """
        Parse a single EVTX record.
        Builds an enriched natural-language message so the hybrid retriever
        receives meaningful semantic content rather than raw field dumps.
        """
        try:
            import xml.etree.ElementTree as ET

            xml_str = record.xml()
            root = ET.fromstring(xml_str)

            ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}

            system = root.find('e:System', ns)
            if system is None:
                system = root.find('System')
                ns = {}

            def find_text(parent, *paths):
                for path in paths:
                    if parent is None:
                        continue
                    el = parent.find(path, ns) if ns else parent.find(path)
                    if el is not None:
                        return (el.text or '').strip()
                return ''

            event_id  = find_text(system, 'e:EventID', 'EventID')
            computer  = find_text(system, 'e:Computer', 'Computer')

            provider_el = (system.find('e:Provider', ns) if ns else system.find('Provider')) if system is not None else None
            provider  = provider_el.get('Name', 'Windows') if provider_el is not None else 'Windows'

            time_el   = (system.find('e:TimeCreated', ns) if ns else system.find('TimeCreated')) if system is not None else None
            timestamp = time_el.get('SystemTime', '') if time_el is not None else ''

            security_el = (system.find('e:Security', ns) if ns else system.find('Security')) if system is not None else None
            user_id   = security_el.get('UserID', '') if security_el is not None else ''

            # Collect all named EventData fields
            data_fields: Dict[str, str] = {}
            event_data_el = root.find('e:EventData', ns) if ns else root.find('EventData')
            if event_data_el is not None:
                for el in event_data_el:
                    name  = el.get('Name', '')
                    value = (el.text or '').strip()
                    if name:
                        data_fields[name] = value

            user_name = (
                data_fields.get('SubjectUserName')
                or data_fields.get('TargetUserName')
                or user_id
            )

            # Build the enriched semantic message
            message = build_enriched_message(event_id, data_fields, computer, user_name)

            return LogEntry(
                timestamp=timestamp,
                source=provider,
                message=message,
                raw={'event_id': event_id, 'data': data_fields},
                event_type=event_id,
                host=computer,
                user=user_name
            )

        except Exception as e:
            logger.warning(f"Failed to parse EVTX record: {e}")
            return None


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

        if log_format == 'evtx':
            yield from self._read_evtx_file(file_path)
            return

        with open(file_path, 'r', errors='replace') as f:
            if log_format == 'json':
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            data = json.loads(line)
                            yield self.parser.parse_json_log(data)
                        except json.JSONDecodeError:
                            continue
            elif log_format == 'json_array':
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

    def _read_evtx_file(self, file_path: Path) -> Generator[LogEntry, None, None]:
        try:
            import Evtx.Evtx as evtx
        except ImportError:
            raise ImportError(
                "python-evtx is required to process .evtx files.\n"
                "Install it with: pip install python-evtx"
            )

        logger.info(f"Reading EVTX file: {file_path}")
        with evtx.Evtx(str(file_path)) as log:
            for record in log.records():
                entry = self.parser.parse_evtx_record(record)
                if entry is not None and entry.message.strip():
                    yield entry

    def process_log_entry(
        self,
        entry: LogEntry,
        previous_tactics: List[str]
    ) -> List[Detection]:

        analysis = self.retriever.analyze_log_entry(
            entry.message,
            previous_detections=[]
        )

        detections = []
        for match in analysis['matches']:
            if match['hybrid_score'] >= 0.3:
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

        logger.info(f"Processing log file: {file_path} (format: {log_format})")

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
                logger.info(f"Processed {log_count} logs, {len(all_detections)} detections so far")

        self.detections = all_detections

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
                for d in all_detections[:100]
            ]
        }

    def store_detections_in_neo4j(self, session_id: str):
        logger.info(f"Storing {len(self.detections)} detections in Neo4j...")

        with self.driver.session() as session:
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
        if not self.detections:
            return "No detections to report."

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
            report.append(f"  Message: {d.log_entry.message[:120]}")

        return "\n".join(report)


def detect_format(file_path: Path) -> str:
    suffix = file_path.suffix.lower()
    if suffix == '.evtx':
        return 'evtx'
    if suffix in ('.json', '.jsonl', '.ndjson'):
        return 'json'
    if suffix in ('.log', '.syslog'):
        return 'syslog'
    if suffix == '.cef':
        return 'cef'
    return 'json'


def main():
    parser = argparse.ArgumentParser(
        description='Analyze security log files against the MITRE ATT&CK framework.'
    )
    parser.add_argument(
        'file',
        type=str,
        help='Path to the log file (e.g. Security.evtx, auth.log, events.json)'
    )
    parser.add_argument(
        '--format', '-f',
        type=str,
        choices=['evtx', 'json', 'json_array', 'syslog', 'cef'],
        default=None,
        help='Log format. Auto-detected from file extension if omitted.'
    )
    parser.add_argument(
        '--store', '-s',
        action='store_true',
        help='Store detections in Neo4j after analysis.'
    )
    parser.add_argument(
        '--output', '-o',
        type=str,
        default=None,
        help='Write the report to this file instead of stdout.'
    )

    args = parser.parse_args()

    file_path = Path(args.file)
    if not file_path.exists():
        print(f"ERROR: File not found: {file_path}")
        sys.exit(1)

    log_format = args.format or detect_format(file_path)
    logger.info(f"Using format: {log_format}")

    processor = SecurityLogProcessor()

    try:
        result = processor.process_log_file(file_path, log_format=log_format)
        report = processor.generate_report()

        if args.output:
            out_path = Path(args.output)
            out_path.write_text(report)
            print(f"Report written to: {out_path}")
        else:
            print(report)

        if args.store:
            session_id = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            processor.store_detections_in_neo4j(session_id)
            print(f"\nDetections stored in Neo4j under session: {session_id}")

    finally:
        processor.close()


if __name__ == "__main__":
    main()