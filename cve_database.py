#!/usr/bin/env python3
"""
CVE Vulnerability Database
Base de datos de vulnerabilidades conocidas estilo CVE
"""

import json
import sqlite3
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, date
from pathlib import Path
import re
import hashlib
from enum import Enum

class VulnerabilitySeverity(Enum):
    """Niveles de severidad"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

class VulnerabilityType(Enum):
    """Tipos de vulnerabilidades"""
    REENTRANCY = "Reentrancy"
    INTEGER_OVERFLOW = "Integer Overflow"
    ACCESS_CONTROL = "Access Control"
    LOGIC_BOMB = "Logic Bomb"
    TIMESTAMP_DEPENDENCY = "Timestamp Dependency"
    DELEGATECALL = "Delegatecall"
    SELFDESTRUCT = "Selfdestruct"
    GAS_LIMIT = "Gas Limit"
    UNINITIALIZED_POINTER = "Uninitialized Pointer"
    RACE_CONDITION = "Race Condition"
    FRONT_RUNNING = "Front Running"
    FLASH_LOAN = "Flash Loan Attack"
    ORACLE_MANIPULATION = "Oracle Manipulation"
    PROXY_VULNERABILITY = "Proxy Vulnerability"
    UPGRADEABILITY = "Upgradeability Issue"
    ERC20_VIOLATION = "ERC20 Violation"
    NFT_VIOLATION = "NFT Violation"
    DEFI_VULNERABILITY = "DeFi Vulnerability"
    RANDOMNESS = "Randomness Issue"
    STORAGE_COLLISION = "Storage Collision"

@dataclass
class CVEEntry:
    """Entrada de CVE"""
    cve_id: str
    title: str
    description: str
    severity: VulnerabilitySeverity
    vulnerability_type: VulnerabilityType
    discovered_date: date
    published_date: date
    last_modified: date
    affected_versions: List[str]
    affected_platforms: List[str]
    affected_contracts: List[str]
    exploit_available: bool
    exploit_complexity: str  # Low, Medium, High
    exploit_mitigation: str
    references: List[str]
    tags: List[str]
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe_id: Optional[str] = None
    patches_available: bool = False
    patch_urls: List[str] = None
    similar_cves: List[str] = None
    verified: bool = False
    verification_source: Optional[str] = None

@dataclass
class VulnerabilityPattern:
    """Patrón de vulnerabilidad para matching"""
    pattern_id: str
    name: str
    description: str
    vulnerability_type: VulnerabilityType
    severity: VulnerabilitySeverity
    solidity_patterns: List[str]
    bytecode_patterns: List[str]
    gas_patterns: List[str]
    control_flow_patterns: List[str]
    detection_rules: Dict[str, Any]
    false_positive_rate: float
    true_positive_rate: float
    confidence_threshold: float

class CVEDatabase:
    """Base de datos de vulnerabilidades CVE"""
    
    def __init__(self, db_path: str = None):
        self.db_path = Path(db_path) if db_path else Path(__file__).parent / "cve_database.sqlite"
        self.db_path.parent.mkdir(exist_ok=True)
        
        self.init_database()
        self.load_default_data()
    
    def init_database(self):
        """Inicializa base de datos"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Tabla de CVEs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cve_entries (
                cve_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL,
                vulnerability_type TEXT NOT NULL,
                discovered_date TEXT NOT NULL,
                published_date TEXT NOT NULL,
                last_modified TEXT NOT NULL,
                affected_versions TEXT,
                affected_platforms TEXT,
                affected_contracts TEXT,
                exploit_available INTEGER,
                exploit_complexity TEXT,
                exploit_mitigation TEXT,
                ref_sources TEXT,
                tags TEXT,
                cvss_score REAL,
                cvss_vector TEXT,
                cwe_id TEXT,
                patches_available INTEGER,
                patch_urls TEXT,
                similar_cves TEXT,
                verified INTEGER,
                verification_source TEXT
            )
        ''')
        
        # Tabla de patrones
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerability_patterns (
                pattern_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                vulnerability_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                solidity_patterns TEXT,
                bytecode_patterns TEXT,
                gas_patterns TEXT,
                control_flow_patterns TEXT,
                detection_rules TEXT,
                false_positive_rate REAL,
                true_positive_rate REAL,
                confidence_threshold REAL
            )
        ''')
        
        # Tabla de similitud
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerability_similarity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id_1 TEXT NOT NULL,
                cve_id_2 TEXT NOT NULL,
                similarity_score REAL NOT NULL,
                similarity_type TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (cve_id_1) REFERENCES cve_entries (cve_id),
                FOREIGN KEY (cve_id_2) REFERENCES cve_entries (cve_id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def load_default_data(self):
        """Carga datos por defecto"""
        # Verificar si ya hay datos
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM cve_entries")
        count = cursor.fetchone()[0]
        conn.close()
        
        if count > 0:
            return
        
        # Cargar CVEs de ejemplo
        default_cves = [
            CVEEntry(
                cve_id="CVE-2023-0001",
                title="Reentrancy Vulnerability in Smart Contract",
                description="Critical reentrancy vulnerability allowing attackers to drain contract funds",
                severity=VulnerabilitySeverity.CRITICAL,
                vulnerability_type=VulnerabilityType.REENTRANCY,
                discovered_date=date(2023, 1, 15),
                published_date=date(2023, 1, 20),
                last_modified=date(2023, 1, 25),
                affected_versions=["0.1.0", "0.1.1"],
                affected_platforms=["Ethereum", "BSC"],
                affected_contracts=["0x1234567890123456789012345678901234567890"],
                exploit_available=True,
                exploit_complexity="Medium",
                exploit_mitigation="Implement reentrancy guards and checks-effects-interactions pattern",
                references=["https://swarm.ethereum.org/articles/reentrancy"],
                tags=["reentrancy", "critical", "defi"],
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-841",
                patches_available=True,
                patch_urls=["https://github.com/project/patch/1"],
                verified=True,
                verification_source="Security Audit"
            ),
            CVEEntry(
                cve_id="CVE-2023-0002",
                title="Integer Overflow in Token Contract",
                description="Integer overflow vulnerability allowing token manipulation",
                severity=VulnerabilitySeverity.HIGH,
                vulnerability_type=VulnerabilityType.INTEGER_OVERFLOW,
                discovered_date=date(2023, 2, 10),
                published_date=date(2023, 2, 15),
                last_modified=date(2023, 2, 20),
                affected_versions=["1.0.0", "1.0.1"],
                affected_platforms=["Ethereum"],
                affected_contracts=["0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"],
                exploit_available=True,
                exploit_complexity="Low",
                exploit_mitigation="Use SafeMath library or Solidity 0.8+ built-in overflow protection",
                references=["https://docs.soliditylang.org/en/v0.8.0/security-considerations.html"],
                tags=["overflow", "token", "erc20"],
                cvss_score=8.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                cwe_id="CWE-190",
                patches_available=True,
                patch_urls=["https://github.com/project/patch/2"],
                verified=True,
                verification_source="Community Report"
            ),
            CVEEntry(
                cve_id="CVE-2023-0003",
                title="Access Control Bypass in Admin Functions",
                description="Access control vulnerability allowing unauthorized admin access",
                severity=VulnerabilitySeverity.HIGH,
                vulnerability_type=VulnerabilityType.ACCESS_CONTROL,
                discovered_date=date(2023, 3, 5),
                published_date=date(2023, 3, 10),
                last_modified=date(2023, 3, 15),
                affected_versions=["2.0.0"],
                affected_platforms=["Polygon", "Arbitrum"],
                affected_contracts=["0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"],
                exploit_available=True,
                exploit_complexity="Medium",
                exploit_mitigation="Implement proper access control modifiers and role-based permissions",
                references=["https://docs.openzeppelin.com/contracts/access-control"],
                tags=["access-control", "admin", "authorization"],
                cvss_score=8.2,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-284",
                patches_available=True,
                patch_urls=["https://github.com/project/patch/3"],
                verified=True,
                verification_source="Security Audit"
            )
        ]
        
        # Cargar patrones de ejemplo
        default_patterns = [
            VulnerabilityPattern(
                pattern_id="PATTERN-001",
                name="Reentrancy Pattern",
                description="Classic reentrancy attack pattern",
                vulnerability_type=VulnerabilityType.REENTRANCY,
                severity=VulnerabilitySeverity.CRITICAL,
                solidity_patterns=[
                    r"function\s+\w+\s*\([^)]*\)\s*(public|external)\s*(payable)?\s*{[^}]*\.call[^}]*}",
                    r"(bool\s+success,\s*)?\.call\{value:\s*\w+\}\([^)]*\)",
                    r"require\(success"
                ],
                bytecode_patterns=[
                    r"f1.*80.*83.*14.*57.*fd"
                ],
                gas_patterns=[
                    r"gas\s*<\s*\d+",
                    r"gasleft\(\)\s*<\s*\d+"
                ],
                control_flow_patterns=[
                    r"external.*call.*before.*state.*change"
                ],
                detection_rules={
                    "min_confidence": 0.8,
                    "max_false_positive_rate": 0.1,
                    "required_patterns": ["solidity_patterns"],
                    "optional_patterns": ["bytecode_patterns"]
                },
                false_positive_rate=0.05,
                true_positive_rate=0.95,
                confidence_threshold=0.85
            ),
            VulnerabilityPattern(
                pattern_id="PATTERN-002",
                name="Integer Overflow Pattern",
                description="Integer overflow/underflow pattern",
                vulnerability_type=VulnerabilityType.INTEGER_OVERFLOW,
                severity=VulnerabilitySeverity.HIGH,
                solidity_patterns=[
                    r"(\w+\s*\+\s*\w+|\w+\s*\*\s*\w+)",
                    r"(uint|int)\d+\s+\w+",
                    r"require\(\w+\s*>\s*0"
                ],
                bytecode_patterns=[
                    r"01.*02.*03.*04"
                ],
                gas_patterns=[],
                control_flow_patterns=[],
                detection_rules={
                    "min_confidence": 0.7,
                    "max_false_positive_rate": 0.15,
                    "required_patterns": ["solidity_patterns"],
                    "check_version": "0.7.0"
                },
                false_positive_rate=0.1,
                true_positive_rate=0.9,
                confidence_threshold=0.8
            )
        ]
        
        # Insertar datos
        self.add_cve_entries(default_cves)
        self.add_vulnerability_patterns(default_patterns)
    
    def add_cve_entry(self, cve_entry: CVEEntry) -> bool:
        """Añade entrada CVE"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO cve_entries VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            ''', (
                cve_entry.cve_id,
                cve_entry.title,
                cve_entry.description,
                cve_entry.severity.value,
                cve_entry.vulnerability_type.value,
                cve_entry.discovered_date.isoformat(),
                cve_entry.published_date.isoformat(),
                cve_entry.last_modified.isoformat(),
                json.dumps(cve_entry.affected_versions),
                json.dumps(cve_entry.affected_platforms),
                json.dumps(cve_entry.affected_contracts),
                int(cve_entry.exploit_available),
                cve_entry.exploit_complexity,
                cve_entry.exploit_mitigation,
                json.dumps(cve_entry.references),
                json.dumps(cve_entry.tags),
                cve_entry.cvss_score,
                cve_entry.cvss_vector,
                cve_entry.cwe_id,
                int(cve_entry.patches_available),
                json.dumps(cve_entry.patch_urls or []),
                json.dumps(cve_entry.similar_cves or []),
                int(cve_entry.verified),
                cve_entry.verification_source
            ))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error adding CVE entry: {e}")
            return False
    
    def add_cve_entries(self, cve_entries: List[CVEEntry]) -> int:
        """Añade múltiples entradas CVE"""
        success_count = 0
        for entry in cve_entries:
            if self.add_cve_entry(entry):
                success_count += 1
        return success_count
    
    def get_cve_entry(self, cve_id: str) -> Optional[CVEEntry]:
        """Obtiene entrada CVE por ID"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM cve_entries WHERE cve_id = ?", (cve_id,))
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return self._row_to_cve_entry(row)
            return None
            
        except Exception as e:
            print(f"Error getting CVE entry: {e}")
            return None
    
    def _row_to_cve_entry(self, row: Tuple) -> CVEEntry:
        """Convierte fila de BD a objeto CVEEntry"""
        return CVEEntry(
            cve_id=row[0],
            title=row[1],
            description=row[2],
            severity=VulnerabilitySeverity(row[3]),
            vulnerability_type=VulnerabilityType(row[4]),
            discovered_date=date.fromisoformat(row[5]),
            published_date=date.fromisoformat(row[6]),
            last_modified=date.fromisoformat(row[7]),
            affected_versions=json.loads(row[8]),
            affected_platforms=json.loads(row[9]),
            affected_contracts=json.loads(row[10]),
            exploit_available=bool(row[11]),
            exploit_complexity=row[12],
            exploit_mitigation=row[13],
            references=json.loads(row[14]),
            tags=json.loads(row[15]),
            cvss_score=row[16],
            cvss_vector=row[17],
            cwe_id=row[18],
            patches_available=bool(row[19]),
            patch_urls=json.loads(row[20]),
            similar_cves=json.loads(row[21]),
            verified=bool(row[22]),
            verification_source=row[23]
        )
    
    def search_cves(self, query: str, filters: Dict[str, Any] = None) -> List[CVEEntry]:
        """Busca CVEs por texto y filtros"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Query base
            sql = """
                SELECT * FROM cve_entries 
                WHERE (title LIKE ? OR description LIKE ? OR tags LIKE ?)
            """
            params = [f"%{query}%", f"%{query}%", f"%{query}%"]
            
            # Añadir filtros
            if filters:
                if "severity" in filters:
                    sql += " AND severity = ?"
                    params.append(filters["severity"])
                
                if "vulnerability_type" in filters:
                    sql += " AND vulnerability_type = ?"
                    params.append(filters["vulnerability_type"])
                
                if "exploit_available" in filters:
                    sql += " AND exploit_available = ?"
                    params.append(int(filters["exploit_available"]))
                
                if "verified" in filters:
                    sql += " AND verified = ?"
                    params.append(int(filters["verified"]))
            
            sql += " ORDER BY published_date DESC"
            
            cursor.execute(sql, params)
            rows = cursor.fetchall()
            conn.close()
            
            return [self._row_to_cve_entry(row) for row in rows]
            
        except Exception as e:
            print(f"Error searching CVEs: {e}")
            return []
    
    def get_similar_cves(self, cve_id: str, threshold: float = 0.7) -> List[Tuple[str, float]]:
        """Obtiene CVEs similares"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT cve_id_2, similarity_score 
                FROM vulnerability_similarity 
                WHERE cve_id_1 = ? AND similarity_score >= ?
                ORDER BY similarity_score DESC
            ''', (cve_id, threshold))
            
            rows = cursor.fetchall()
            conn.close()
            
            return rows
            
        except Exception as e:
            print(f"Error getting similar CVEs: {e}")
            return []
    
    def add_vulnerability_pattern(self, pattern: VulnerabilityPattern) -> bool:
        """Añade patrón de vulnerabilidad"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO vulnerability_patterns VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            ''', (
                pattern.pattern_id,
                pattern.name,
                pattern.description,
                pattern.vulnerability_type.value,
                pattern.severity.value,
                json.dumps(pattern.solidity_patterns),
                json.dumps(pattern.bytecode_patterns),
                json.dumps(pattern.gas_patterns),
                json.dumps(pattern.control_flow_patterns),
                json.dumps(pattern.detection_rules),
                pattern.false_positive_rate,
                pattern.true_positive_rate,
                pattern.confidence_threshold
            ))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error adding vulnerability pattern: {e}")
            return False
    
    def add_vulnerability_patterns(self, patterns: List[VulnerabilityPattern]) -> int:
        """Añade múltiples patrones"""
        success_count = 0
        for pattern in patterns:
            if self.add_vulnerability_pattern(pattern):
                success_count += 1
        return success_count
    
    def get_vulnerability_patterns(self, vulnerability_type: VulnerabilityType = None) -> List[VulnerabilityPattern]:
        """Obtiene patrones de vulnerabilidad"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if vulnerability_type:
                cursor.execute("SELECT * FROM vulnerability_patterns WHERE vulnerability_type = ?", 
                             (vulnerability_type.value,))
            else:
                cursor.execute("SELECT * FROM vulnerability_patterns")
            
            rows = cursor.fetchall()
            conn.close()
            
            return [self._row_to_pattern(row) for row in rows]
            
        except Exception as e:
            print(f"Error getting vulnerability patterns: {e}")
            return []
    
    def _row_to_pattern(self, row: Tuple) -> VulnerabilityPattern:
        """Convierte fila de BD a objeto VulnerabilityPattern"""
        return VulnerabilityPattern(
            pattern_id=row[0],
            name=row[1],
            description=row[2],
            vulnerability_type=VulnerabilityType(row[3]),
            severity=VulnerabilitySeverity(row[4]),
            solidity_patterns=json.loads(row[5]),
            bytecode_patterns=json.loads(row[6]),
            gas_patterns=json.loads(row[7]),
            control_flow_patterns=json.loads(row[8]),
            detection_rules=json.loads(row[9]),
            false_positive_rate=row[10],
            true_positive_rate=row[11],
            confidence_threshold=row[12]
        )
    
    def match_patterns(self, code: str, bytecode: str = None, gas_analysis: Dict = None) -> List[Dict]:
        """Matchea patrones contra código"""
        matches = []
        patterns = self.get_vulnerability_patterns()
        
        for pattern in patterns:
            # Match contra código Solidity
            solidity_matches = []
            for solid_pattern in pattern.solidity_patterns:
                if re.search(solid_pattern, code, re.IGNORECASE):
                    solidity_matches.append(solid_pattern)
            
            # Match contra bytecode
            bytecode_matches = []
            if bytecode and pattern.bytecode_patterns:
                for byte_pattern in pattern.bytecode_patterns:
                    if re.search(byte_pattern, bytecode, re.IGNORECASE):
                        bytecode_matches.append(byte_pattern)
            
            # Match contra análisis de gas
            gas_matches = []
            if gas_analysis and pattern.gas_patterns:
                for gas_pattern in pattern.gas_patterns:
                    gas_text = str(gas_analysis)
                    if re.search(gas_pattern, gas_text, re.IGNORECASE):
                        gas_matches.append(gas_pattern)
            
            # Calcular confianza
            confidence = self._calculate_pattern_confidence(
                pattern, solidity_matches, bytecode_matches, gas_matches
            )
            
            if confidence >= pattern.confidence_threshold:
                matches.append({
                    'pattern': pattern,
                    'solidity_matches': solidity_matches,
                    'bytecode_matches': bytecode_matches,
                    'gas_matches': gas_matches,
                    'confidence': confidence,
                    'severity': pattern.severity,
                    'vulnerability_type': pattern.vulnerability_type
                })
        
        return matches
    
    def _calculate_pattern_confidence(self, pattern: VulnerabilityPattern, 
                                    solidity_matches: List[str], 
                                    bytecode_matches: List[str], 
                                    gas_matches: List[str]) -> float:
        """Calcula confianza del match"""
        confidence = 0.0
        
        # Ponderar diferentes tipos de matches
        if solidity_matches:
            confidence += 0.6 * (len(solidity_matches) / len(pattern.solidity_patterns))
        
        if bytecode_matches:
            confidence += 0.3 * (len(bytecode_matches) / len(pattern.bytecode_patterns))
        
        if gas_matches:
            confidence += 0.1 * (len(gas_matches) / len(pattern.gas_patterns))
        
        return min(confidence, 1.0)
    
    def calculate_similarity(self, cve_id_1: str, cve_id_2: str) -> float:
        """Calcula similitud entre dos CVEs"""
        cve_1 = self.get_cve_entry(cve_id_1)
        cve_2 = self.get_cve_entry(cve_id_2)
        
        if not cve_1 or not cve_2:
            return 0.0
        
        similarity = 0.0
        
        # Similitud de tipo de vulnerabilidad
        if cve_1.vulnerability_type == cve_2.vulnerability_type:
            similarity += 0.3
        
        # Similitud de severidad
        severity_weights = {
            VulnerabilitySeverity.CRITICAL: 1.0,
            VulnerabilitySeverity.HIGH: 0.8,
            VulnerabilitySeverity.MEDIUM: 0.6,
            VulnerabilitySeverity.LOW: 0.4,
            VulnerabilitySeverity.INFO: 0.2
        }
        similarity += 0.2 * (1 - abs(severity_weights[cve_1.severity] - severity_weights[cve_2.severity]))
        
        # Similitud de descripción (simple)
        words_1 = set(cve_1.description.lower().split())
        words_2 = set(cve_2.description.lower().split())
        if words_1 and words_2:
            text_similarity = len(words_1.intersection(words_2)) / len(words_1.union(words_2))
            similarity += 0.3 * text_similarity
        
        # Similitud de tags
        tags_1 = set(cve_1.tags)
        tags_2 = set(cve_2.tags)
        if tags_1 and tags_2:
            tag_similarity = len(tags_1.intersection(tags_2)) / len(tags_1.union(tags_2))
            similarity += 0.2 * tag_similarity
        
        return similarity
    
    def update_similarity_cache(self):
        """Actualiza caché de similitudes"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Limpiar caché existente
        cursor.execute("DELETE FROM vulnerability_similarity")
        
        # Obtener todos los CVEs
        cursor.execute("SELECT cve_id FROM cve_entries")
        cve_ids = [row[0] for row in cursor.fetchall()]
        
        # Calcular similitudes
        for i, cve_id_1 in enumerate(cve_ids):
            for cve_id_2 in cve_ids[i+1:]:
                similarity = self.calculate_similarity(cve_id_1, cve_id_2)
                
                if similarity >= 0.5:  # Solo guardar similitudes significativas
                    cursor.execute('''
                        INSERT INTO vulnerability_similarity 
                        (cve_id_1, cve_id_2, similarity_score, similarity_type, created_at)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (cve_id_1, cve_id_2, similarity, "automatic", datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Obtiene estadísticas de la base de datos"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        # Total CVEs
        cursor.execute("SELECT COUNT(*) FROM cve_entries")
        stats['total_cves'] = cursor.fetchone()[0]
        
        # CVEs por severidad
        cursor.execute("SELECT severity, COUNT(*) FROM cve_entries GROUP BY severity")
        stats['cves_by_severity'] = dict(cursor.fetchall())
        
        # CVEs por tipo
        cursor.execute("SELECT vulnerability_type, COUNT(*) FROM cve_entries GROUP BY vulnerability_type")
        stats['cves_by_type'] = dict(cursor.fetchall())
        
        # CVEs con exploits
        cursor.execute("SELECT COUNT(*) FROM cve_entries WHERE exploit_available = 1")
        stats['cves_with_exploits'] = cursor.fetchone()[0]
        
        # CVEs verificados
        cursor.execute("SELECT COUNT(*) FROM cve_entries WHERE verified = 1")
        stats['verified_cves'] = cursor.fetchone()[0]
        
        # Total patrones
        cursor.execute("SELECT COUNT(*) FROM vulnerability_patterns")
        stats['total_patterns'] = cursor.fetchone()[0]
        
        conn.close()
        return stats

# Demo
def demo_cve_database():
    """Demostración de la base de datos CVE"""
    print("=== CVE Database Demo ===")
    
    # Crear base de datos
    cve_db = CVEDatabase()
    
    # Buscar CVEs
    results = cve_db.search_cves("reentrancy")
    print(f"Found {len(results)} CVEs for 'reentrancy'")
    
    for cve in results:
        print(f"- {cve.cve_id}: {cve.title} ({cve.severity.value})")
    
    # Matchear patrones
    code = """
    contract Vulnerable {
        mapping(address => uint) public balances;
        
        function withdraw(uint amount) public {
            require(balances[msg.sender] >= amount);
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success);
            balances[msg.sender] -= amount;
        }
    }
    """
    
    matches = cve_db.match_patterns(code)
    print(f"\nPattern matches: {len(matches)}")
    
    for match in matches:
        print(f"- {match['pattern'].name}: {match['confidence']:.2%} confidence")
    
    # Estadísticas
    stats = cve_db.get_statistics()
    print(f"\nDatabase Statistics:")
    print(f"- Total CVEs: {stats['total_cves']}")
    print(f"- CVEs with exploits: {stats['cves_with_exploits']}")
    print(f"- Verified CVEs: {stats['verified_cves']}")
    print(f"- Total patterns: {stats['total_patterns']}")

if __name__ == "__main__":
    demo_cve_database()
