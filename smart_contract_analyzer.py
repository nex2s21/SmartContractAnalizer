#!/usr/bin/env python3
"""
Smart Contract Analyzer - Enhanced Version
Análisis avanzado de contratos inteligentes con Machine Learning y detección de scams
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from tkinter.font import Font
import threading
import os
import sys
import json
import random
import math
from dataclasses import dataclass
from enum import Enum
from tkinter import Canvas
import time
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import random
import math
from dataclasses import dataclass
from enum import Enum

# Import new modules
try:
    from blockchain_integration import BlockchainExplorer, EtherscanExplorer, OnChainAnalyzer
    from reporting_system import ReportingSystem, ReportData
    from batch_analyzer import BatchAnalyzer
    from bytecode_analyzer import BytecodeAnalyzer
    from plugin_system import PluginManager
    from cve_database import CVEDatabase
except ImportError:
    print("Warning: Advanced modules not available. Some features will be disabled.")
    BlockchainExplorer = None
    EtherscanExplorer = None
    OnChainAnalyzer = None
    ReportingSystem = None
    ReportData = None
    BatchAnalyzer = None
    BytecodeAnalyzer = None
    PluginManager = None
    CVEDatabase = None

class Severity(Enum):
    """Niveles de severidad para hallazgos"""
    CRITICAL = "Crítico"
    HIGH = "Alto"
    MEDIUM = "Medio"
    LOW = "Bajo"
    INFO = "Info"

class ScamType(Enum):
    """Tipos de scams detectados"""
    HONEYPOT = "Honeypot"
    RUG_PULL = "Rug Pull"
    PHISHING = "Phishing"
    FLASH_LOAN_ATTACK = "Flash Loan Attack"
    MEV_MANIPULATION = "MEV Manipulation"
    SANDWICH_ATTACK = "Sandwich Attack"
    BACKDOOR = "Backdoor Function"
    REENTRANCY = "Reentrancy Attack"
    UNLIMITED_MINT = "Unlimited Mint"
    BLACKLIST = "Blacklist Function"

@dataclass
class Finding:
    """Estructura para hallazgos de seguridad"""
    title: str
    description: str
    severity: Severity
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    recommendation: Optional[str] = None

@dataclass
class MLAnalysisResult:
    """Resultado del análisis de Machine Learning"""
    risk_score: float
    confidence: float
    scam_type: Optional[ScamType]
    features: Dict[str, float]
    explanation: str

@dataclass
class BehavioralAnalysisResult:
    """Resultado del análisis comportamental"""
    suspicious_patterns: List[str]
    transaction_risk: float
    gas_anomalies: List[str]
    timing_anomalies: List[str]

class MLScamDetector:
    """Detector de scams usando Machine Learning"""
    
    def __init__(self):
        self.weights = {
            'code_complexity': 0.15,
            'external_calls': 0.20,
            'owner_functions': 0.18,
            'modifier_usage': 0.12,
            'string_patterns': 0.15,
            'function_count': 0.10,
            'contract_size': 0.10
        }
    
    def extract_features(self, code: str) -> Dict[str, float]:
        """Extrae características del código para ML"""
        features = {}
        
        # Complejidad del código
        lines = code.split('\n')
        features['code_complexity'] = min(len([l for l in lines if '{' in l or '}' in l]) / max(len(lines), 1), 1.0)
        
        # Llamadas externas
        external_patterns = ['call(', 'delegatecall(', 'staticcall(', 'send(', 'transfer(']
        features['external_calls'] = min(sum(code.count(p) for p in external_patterns) / 20.0, 1.0)
        
        # Funciones de owner
        owner_patterns = ['owner', 'onlyOwner', 'transferOwnership', 'renounceOwnership']
        features['owner_functions'] = min(sum(code.count(p) for p in owner_patterns) / 10.0, 1.0)
        
        # Uso de modificadores
        features['modifier_usage'] = min(code.count('modifier') / 5.0, 1.0)
        
        # Patrones de strings sospechosos
        suspicious_strings = ['blacklist', 'honeypot', 'backdoor', 'malicious', 'steal', 'drain']
        features['string_patterns'] = min(sum(code.lower().count(s) for s in suspicious_strings) / 5.0, 1.0)
        
        # Conteo de funciones
        features['function_count'] = min(code.count('function') / 50.0, 1.0)
        
        # Tamaño del contrato
        features['contract_size'] = min(len(code) / 50000.0, 1.0)
        
        return features
    
    def predict_risk(self, features: Dict[str, float]) -> MLAnalysisResult:
        """Predice el riesgo usando el modelo ML"""
        # Cálculo del risk score
        risk_score = sum(features[k] * self.weights[k] for k in self.weights)
        
        # Determinar tipo de scam basado en características
        scam_type = None
        if features['external_calls'] > 0.7:
            scam_type = ScamType.REENTRANCY
        elif features['owner_functions'] > 0.6:
            scam_type = ScamType.RUG_PULL
        elif features['string_patterns'] > 0.4:
            scam_type = ScamType.HONEYPOT
        elif features['modifier_usage'] > 0.5:
            scam_type = ScamType.BACKDOOR
        
        # Explicación
        explanation = f"Análisis ML muestra riesgo del {risk_score:.2%} basado en:\n"
        for feature, value in features.items():
            if value > 0.3:
                explanation += f"- {feature}: {value:.2%}\n"
        
        confidence = min(risk_score + 0.2, 1.0)
        
        return MLAnalysisResult(
            risk_score=risk_score,
            confidence=confidence,
            scam_type=scam_type,
            features=features,
            explanation=explanation
        )

class BehavioralAnalyzer:
    """Analizador de patrones comportamentales"""
    
    def analyze_patterns(self, code: str) -> BehavioralAnalysisResult:
        """Analiza patrones comportamentales sospechosos"""
        suspicious_patterns = []
        gas_anomalies = []
        timing_anomalies = []
        
        # Patrones sospechosos
        if 'require(msg.value == 0)' in code:
            suspicious_patterns.append("Transacción sin valor requerida")
        
        if 'block.timestamp' in code and code.count('block.timestamp') > 3:
            timing_anomalies.append("Uso excesivo de timestamp")
        
        if 'gasleft()' in code:
            gas_anomalies.append("Manipulación de gas detectada")
        
        if code.count('transfer(') > 10:
            suspicious_patterns.append("Múltiples transferencias")
        
        # Calcular riesgo general
        total_anomalies = len(suspicious_patterns) + len(gas_anomalies) + len(timing_anomalies)
        transaction_risk = min(total_anomalies / 10.0, 1.0)
        
        return BehavioralAnalysisResult(
            suspicious_patterns=suspicious_patterns,
            transaction_risk=transaction_risk,
            gas_anomalies=gas_anomalies,
            timing_anomalies=timing_anomalies
        )

class SecurityAnalyzer:
    """Analizador de seguridad principal"""
    
    def __init__(self):
        self.ml_detector = MLScamDetector()
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.setup_patterns()
    
    def setup_patterns(self):
        """Configura patrones de detección avanzados"""
        self.malicious_patterns = {
            # Honeypot patterns
            'honeypot_transfer_block': [
                r'require\(.*transfer.*\s*==\s*0\)',
                r'require\(.*balance.*\[.*\].*>\s*0\)',
                r'onlyOwner.*transfer'
            ],
            
            # Rug pull patterns
            'rug_pull_ownership': [
                r'transferOwnership\(.*\)',
                r'renounceOwnership\(\)',
                r'owner.*=.*address\(0\)'
            ],
            
            # Phishing patterns
            'phishing_approval': [
                r'approve\(.*\)',
                r'allowance\(.*\)',
                r'setApprovalForAll\(.*\)'
            ],
            
            # Flash loan attack patterns
            'flash_loan_vulnerable': [
                r'function.*flash.*loan',
                r'uniswapV2Call',
                r'executeSwap'
            ],
            
            # MEV manipulation
            'mev_manipulation': [
                r'block\.timestamp',
                r'block\.difficulty',
                r'block\.gaslimit'
            ],
            
            # Sandwich attack
            'sandwich_attack': [
                r'swapExactTokensForTokens',
                r'getAmountsOut',
                r'front.*run'
            ],
            
            # Backdoor functions
            'backdoor_functions': [
                r'function.*backdoor',
                r'function.*emergency',
                r'function.*admin'
            ],
            
            # Reentrancy
            'reentrancy_vulnerable': [
                r'\.call\{value:\s*\}',
                r'external.*call',
                r'selfdestruct'
            ],
            
            # Unlimited mint
            'unlimited_mint': [
                r'_mint\(.*\)',
                r'mint\(.*\)',
                r'totalSupply.*\+\+'
            ],
            
            # Blacklist
            'blacklist_functions': [
                r'blacklist',
                r'isBlacklisted',
                r'addToBlacklist'
            ],
            
            # Advanced Gas Manipulation Patterns
            'gas_manipulation_advanced': [
                r'gasleft\(\)',
                r'gas\(\)',
                r'gasprice\(\)',
                r'tx\.gasprice',
                r'block\.gaslimit'
            ],
            
            # Integer Overflow/Underflow
            'integer_overflow': [
                r'balance.*\+.*amount',
                r'totalSupply.*\+.*',
                r'allowance.*\+.*',
                r'balance.*-.*amount',
                r'totalSupply.*-.*',
                r'allowance.*-.*'
            ],
            
            # Access Control Issues
            'access_control_bypass': [
                r'modifier.*onlyOwner',
                r'require\(msg\.sender.*owner\)',
                r'require\(msg\.sender.*!=.*address\(0\)\)',
                r'internal.*function'
            ],
            
            # Logic Bombs
            'logic_bomb': [
                r'block\.timestamp.*>',
                r'block\.number.*>',
                r'require\(block\.timestamp.*\)',
                r'require\(block\.number.*\)'
            ],
            
            # Unchecked External Calls
            'unchecked_calls': [
                r'\.call\{.*\}',
                r'\.send\(',
                r'\.transfer\(',
                r'address\(',
                r'payable\('
            ],
            
            # Delegatecall Vulnerabilities
            'delegatecall_vulnerable': [
                r'delegatecall\(',
                r'\.delegatecall\(',
                r'storage\.address',
                r'implementation\.address'
            ],
            
            # Storage Collision
            'storage_collision': [
                r'storage.*slot',
                r'assembly.*sstore',
                r'assembly.*sload',
                r'storage.*uint'
            ],
            
            # Price Oracle Manipulation
            'oracle_manipulation': [
                r'getPrice\(',
                r'price.*=.*',
                r'oracle.*=.*',
                r'setPrice\('
            ],
            
            # Proxy Pattern Issues
            'proxy_vulnerabilities': [
                r'fallback\(\)',
                r'receive\(\)',
                r'delegatecall\(',
                r'implementation.*='
            ],
            
            # Upgradeability Issues
            'upgradeability_issues': [
                r'upgradeTo\(',
                r'upgradeToAndCall\(',
                r'implementation.*=',
                r'proxy.*='
            ],
            
            # Token Standards Violations
            'erc20_violations': [
                r'transfer.*return.*bool',
                r'approve.*return.*bool',
                r'transferFrom.*return.*bool',
                r'return.*true'
            ],
            
            # NFT Specific Issues
            'nft_vulnerabilities': [
                r'tokenOfOwnerByIndex\(',
                r'tokenByIndex\(',
                r'approve.*all',
                r'setApprovalForAll\('
            ],
            
            # DeFi Specific Patterns
            'defi_vulnerabilities': [
                r'addLiquidity\(',
                r'removeLiquidity\(',
                r'swap\(',
                r'getAmountsOut\(',
                r'calculateK\('
            ],
            
            # Time-based Attacks
            'time_manipulation': [
                r'block\.timestamp',
                r'block\.number',
                r'now',
                r'time\.now'
            ],
            
            # Randomness Issues
            'randomness_vulnerable': [
                r'keccak256\(.*block\)',
                r'block\.difficulty',
                r'block\.timestamp',
                r'blockhash\(.*\)'
            ],
            
            # Suicide/Selfdestruct
            'selfdestruct_patterns': [
                r'selfdestruct\(',
                r'suicide\(',
                r'destroy\(',
                r'kill\('
            ]
        }
    
    def analyze_code(self, code: str) -> Tuple[List[Finding], MLAnalysisResult, BehavioralAnalysisResult]:
        """Analiza el código completo"""
        findings = []
        
        # Análisis de patrones básicos
        for pattern_name, patterns in self.malicious_patterns.items():
            for pattern in patterns:
                matches = list(re.finditer(pattern, code, re.IGNORECASE))
                for match in matches:
                    line_num = code[:match.start()].count('\n') + 1
                    line_content = code.split('\n')[line_num-1].strip()
                    
                    severity = self._determine_severity(pattern_name)
                    finding = Finding(
                        title=self._get_pattern_title(pattern_name),
                        description=f"Patrón sospechoso detectado: {pattern_name}",
                        severity=severity,
                        line_number=line_num,
                        code_snippet=line_content,
                        recommendation=self._get_recommendation(pattern_name)
                    )
                    findings.append(finding)
        
        # Análisis avanzado de control flow
        findings.extend(self._analyze_control_flow(code))
        
        # Análisis de complejidad ciclomática
        findings.extend(self._analyze_complexity(code))
        
        # Análisis de patrones de gas avanzados
        findings.extend(self._analyze_gas_patterns(code))
        
        # Análisis de dependencias externas
        findings.extend(self._analyze_external_dependencies(code))
        
        # Análisis de mutabilidad de estado
        findings.extend(self._analyze_state_mutation(code))
        
        # Análisis ML
        ml_result = self.ml_detector.predict_risk(self.ml_detector.extract_features(code))
        
        # Análisis comportamental
        behavioral_result = self.behavioral_analyzer.analyze_patterns(code)
        
        return findings, ml_result, behavioral_result
    
    def _analyze_control_flow(self, code: str) -> List[Finding]:
        """Análisis avanzado de flujo de control"""
        findings = []
        lines = code.split('\n')
        
        # Detectar bucles anidados complejos
        nested_loops = 0
        max_nested = 0
        for i, line in enumerate(lines):
            if any(keyword in line for keyword in ['for(', 'while(', 'do{']):
                nested_loops += 1
                max_nested = max(max_nested, nested_loops)
            elif '}' in line and nested_loops > 0:
                nested_loops -= 1
        
        if max_nested > 3:
            findings.append(Finding(
                title="Control Flow Complejo - Bucles Anidados",
                description=f"Detectados {max_nested} niveles de bucles anidados",
                severity=Severity.MEDIUM,
                recommendation="Simplificar la lógica de bucles para evitar ataques de DoS por gas"
            ))
        
        # Detectar recursión potencialmente infinita
        function_calls = {}
        for i, line in enumerate(lines):
            if 'function' in line and '(' in line:
                func_name = re.search(r'function\s+(\w+)', line)
                if func_name:
                    function_calls[func_name.group(1)] = []
            elif 'call(' in line or 'delegatecall(' in line:
                for func_name in function_calls:
                    if func_name in line:
                        function_calls[func_name].append(func_name)
        
        for func_name, calls in function_calls.items():
            if func_name in calls:
                findings.append(Finding(
                    title="Recursión Potencialmente Infinita",
                    description=f"La función {func_name} puede llamarse a sí misma",
                    severity=Severity.HIGH,
                    recommendation="Implementar guards de recursión o eliminar recursión"
                ))
        
        return findings
    
    def _analyze_complexity(self, code: str) -> List[Finding]:
        """Análisis de complejidad ciclomática"""
        findings = []
        
        # Calcular complejidad ciclomática
        complexity_keywords = ['if', 'else', 'while', 'for', 'case', 'catch', '&&', '||', '?']
        complexity = 0
        lines = code.split('\n')
        
        for line in lines:
            for keyword in complexity_keywords:
                complexity += line.count(keyword)
        
        if complexity > 20:
            findings.append(Finding(
                title="Alta Complejidad Ciclomática",
                description=f"Complejidad ciclomática: {complexity}",
                severity=Severity.MEDIUM,
                recommendation="Dividir funciones complejas en funciones más pequeñas"
            ))
        
        return findings
    
    def _analyze_gas_patterns(self, code: str) -> List[Finding]:
        """Análisis avanzado de patrones de gas"""
        findings = []
        lines = code.split('\n')
        
        # Detectar patrones de consumo excesivo de gas
        gas_operations = []
        for i, line in enumerate(lines):
            if any(op in line for op in ['gasleft()', 'gas()', 'tx.gasprice']):
                gas_operations.append((i + 1, line.strip()))
        
        if len(gas_operations) > 3:
            findings.append(Finding(
                title="Manipulación Avanzada de Gas",
                description=f"Detectados {len(gas_operations)} operadores de gas",
                severity=Severity.HIGH,
                recommendation="Evitar manipulación de gas para prevenir ataques"
            ))
        
        # Detectar loops con operaciones costosas
        for i, line in enumerate(lines):
            if 'for(' in line or 'while(' in line:
                # Buscar operaciones costosas dentro del loop
                loop_content = []
                j = i + 1
                brace_count = 0
                while j < len(lines):
                    line_content = lines[j]
                    brace_count += line_content.count('{') - line_content.count('}')
                    loop_content.append(line_content)
                    if brace_count <= 0 and '}' in line_content:
                        break
                    j += 1
                
                loop_str = ' '.join(loop_content)
                expensive_ops = ['keccak256(', 'sha256(', 'ecrecover(', 'modexp(']
                expensive_count = sum(loop_str.count(op) for op in expensive_ops)
                
                if expensive_count > 2:
                    findings.append(Finding(
                        title="Loop con Operaciones Costosas",
                        description=f"Loop con {expensive_count} operaciones criptográficas",
                        severity=Severity.HIGH,
                        line_number=i + 1,
                        recommendation="Mover operaciones costosas fuera del loop o usar caché"
                    ))
        
        return findings
    
    def _analyze_external_dependencies(self, code: str) -> List[Finding]:
        """Análisis de dependencias externas"""
        findings = []
        
        # Detectar llamadas externas sin validación
        external_calls = re.findall(r'(\w+)\.call\{.*?\}', code)
        for call in external_calls:
            if 'require(' not in code[code.find(call):code.find(call) + 200]:
                findings.append(Finding(
                    title="Llamada Externa Sin Validación",
                    description=f"Llamada a {call}.call sin validación adecuada",
                    severity=Severity.HIGH,
                    recommendation="Siempre validar resultados de llamadas externas"
                ))
        
        # Detectar dependencias de oráculos sin validación
        oracle_calls = re.findall(r'(\w+)\.getPrice\(\)', code)
        if len(oracle_calls) > 2:
            findings.append(Finding(
                title="Múltiples Dependencias de Oráculo",
                description=f"Detectadas {len(oracle_calls)} llamadas a oráculos",
                severity=Severity.MEDIUM,
                recommendation="Implementar validación de precios y circuit breakers"
            ))
        
        return findings
    
    def _analyze_state_mutation(self, code: str) -> List[Finding]:
        """Análisis de mutación de estado"""
        findings = []
        lines = code.split('\n')
        
        # Detectar mutación de estado en llamadas externas
        for i, line in enumerate(lines):
            if '.call{' in line or '.send(' in line:
                # Buscar mutaciones de estado después de la llamada externa
                j = i + 1
                mutations_found = False
                while j < len(lines) and j < i + 5:  # Revisar siguientes 5 líneas
                    next_line = lines[j]
                    if any(mutation in next_line for mutation in ['balances[', 'totalSupply', 'allowance[', 'owner =']):
                        mutations_found = True
                        break
                    j += 1
                
                if mutations_found:
                    findings.append(Finding(
                        title="Mutación de Estado Después de Llamada Externa",
                        description="Posible vulnerabilidad de reentrancy",
                        severity=Severity.CRITICAL,
                        line_number=i + 1,
                        recommendation="Usar pattern checks-effects-interactions"
                    ))
        
        # Detectar funciones view que modifican estado
        for i, line in enumerate(lines):
            if 'view' in line and 'function' in line:
                func_content = []
                j = i + 1
                brace_count = 0
                while j < len(lines):
                    line_content = lines[j]
                    brace_count += line_content.count('{') - line_content.count('}')
                    func_content.append(line_content)
                    if brace_count <= 0 and '}' in line_content:
                        break
                    j += 1
                
                func_str = ' '.join(func_content)
                if any(mutation in func_str for mutation in ['balances[', '=', '++', '--']):
                    findings.append(Finding(
                        title="Función View que Modifica Estado",
                        description="Función marcada como view pero modifica estado",
                        severity=Severity.HIGH,
                        line_number=i + 1,
                        recommendation="Remover modificador view o eliminar mutación de estado"
                    ))
        
        return findings
    
    def _determine_severity(self, pattern_name: str) -> Severity:
        """Determina la severidad basada en el patrón"""
        critical_patterns = ['honeypot_transfer_block', 'backdoor_functions', 'selfdestruct']
        high_patterns = ['rug_pull_ownership', 'reentrancy_vulnerable', 'unlimited_mint']
        medium_patterns = ['phishing_approval', 'flash_loan_vulnerable', 'blacklist_functions']
        
        if pattern_name in critical_patterns:
            return Severity.CRITICAL
        elif pattern_name in high_patterns:
            return Severity.HIGH
        elif pattern_name in medium_patterns:
            return Severity.MEDIUM
        else:
            return Severity.LOW
    
    def _get_pattern_title(self, pattern_name: str) -> str:
        """Obtiene título descriptivo del patrón"""
        titles = {
            'honeypot_transfer_block': 'Honeypot - Bloqueo de Transferencias',
            'rug_pull_ownership': 'Rug Pull - Manipulación de Ownership',
            'phishing_approval': 'Phishing - Aprobaciones Maliciosas',
            'flash_loan_vulnerable': 'Vulnerabilidad - Flash Loan Attack',
            'mev_manipulation': 'MEV - Manipulación de Mercado',
            'sandwich_attack': 'Sandwich Attack - Frontrunning',
            'backdoor_functions': 'Backdoor - Funciones Ocultas',
            'reentrancy_vulnerable': 'Reentrancy - Ataque de Reentrada',
            'unlimited_mint': 'Unlimited Mint - Mint Infinito',
            'blacklist_functions': 'Blacklist - Lista Negra',
            'gas_manipulation_advanced': 'Manipulación Avanzada de Gas',
            'integer_overflow': 'Integer Overflow/Underflow',
            'access_control_bypass': 'Bypass de Control de Acceso',
            'logic_bomb': 'Logic Bomb - Temporal Trigger',
            'unchecked_calls': 'Llamadas Externas No Validadas',
            'delegatecall_vulnerable': 'Delegatecall Vulnerable',
            'storage_collision': 'Storage Collision',
            'oracle_manipulation': 'Manipulación de Oráculo',
            'proxy_vulnerabilities': 'Proxy Contract Vulnerabilities',
            'upgradeability_issues': 'Problemas de Actualización',
            'erc20_violations': 'Violaciones de Estándar ERC20',
            'nft_vulnerabilities': 'Vulnerabilidades NFT',
            'defi_vulnerabilities': 'Vulnerabilidades DeFi',
            'time_manipulation': 'Manipulación Temporal',
            'randomness_vulnerable': 'Randomness Vulnerable',
            'selfdestruct_patterns': 'Selfdestruct/Suicide Patterns'
        }
        return titles.get(pattern_name, pattern_name.replace('_', ' ').title())
    
    def _get_recommendation(self, pattern_name: str) -> str:
        """Obtiene recomendación para el patrón"""
        recommendations = {
            'honeypot_transfer_block': 'Implementar controles de transferencia transparentes y evitar bloqueos injustificados.',
            'rug_pull_ownership': 'Usar contratos de ownership con tiempo de bloqueo y multisig.',
            'phishing_approval': 'Implementar verificación de approvals y límites de transferencia.',
            'flash_loan_vulnerable': 'Añadir controles de reentrada y validación de estados.',
            'mev_manipulation': 'Evitar usar block.timestamp/block.difficulty para randomness crítico.',
            'sandwich_attack': 'Implementar slippage protection y ordenamiento justo.',
            'backdoor_functions': 'Eliminar funciones backdoor o implementar gobernanza transparente.',
            'reentrancy_vulnerable': 'Usar pattern checks-effects-interactions y ReentrancyGuard.',
            'unlimited_mint': 'Implementar límites de mint y validación de supply.',
            'blacklist_functions': 'Evitar blacklist o implementarlo con gobernanza comunitaria.',
            'gas_manipulation_advanced': 'Evitar manipulación de gas y usar límites de gas razonables.',
            'integer_overflow': 'Usar SafeMath o Solidity 0.8+ con overflow protection.',
            'access_control_bypass': 'Implementar proper modifiers y validación de permisos.',
            'logic_bomb': 'Evitar triggers temporales o implementar circuit breakers.',
            'unchecked_calls': 'Siempre validar el resultado de llamadas externas.',
            'delegatecall_vulnerable': 'Usar delegatecall con precaución y validación de storage.',
            'storage_collision': 'Asegurar layouts de storage no colisionen entre contratos.',
            'oracle_manipulation': 'Implementar validación de precios y múltiples oráculos.',
            'proxy_vulnerabilities': 'Usar patrones proxy seguros como EIP-1967.',
            'upgradeability_issues': 'Implementar upgradeability segura con gobernanza.',
            'erc20_violations': 'Seguir el estándar ERC20 e implementar return values.',
            'nft_vulnerabilities': 'Implementar proper NFT estándares y validaciones.',
            'defi_vulnerabilities': 'Usar patrones DeFi probados y auditorías de seguridad.',
            'time_manipulation': 'Evitar dependencia de timestamp para lógica crítica.',
            'randomness_vulnerable': 'Usar oráculos de randomness como Chainlink VRF.',
            'selfdestruct_patterns': 'Evitar selfdestruct o implementarlo con controles estrictos.'
        }
        return recommendations.get(pattern_name, 'Revisar y mejorar la implementación de seguridad.')

class SmartContractAnalyzerGUI:
    """Interfaz gráfica principal del analizador"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Smart Contract Analyzer - Enhanced Version")
        self.root.geometry("1200x800")
        
        self.analyzer = SecurityAnalyzer()
        self.setup_ui()
        
    def setup_ui(self):
        """Configura la interfaz de usuario"""
        # Frame principal
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configurar grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(3, weight=1)
        
        # Header con gradiente
        header_frame = ttk.Frame(main_frame)
        header_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))
        header_frame.columnconfigure(0, weight=1)
        
        # Canvas para gradiente
        canvas = Canvas(header_frame, height=60, highlightthickness=0)
        canvas.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        # Crear gradiente
        for i in range(60):
            color = self._interpolate_color("#2E4057", "#048A81", i/60)
            canvas.create_line(0, i, 1000, i, fill=color, width=1)
        
        # Título
        title_label = tk.Label(canvas, text="🔍 Smart Contract Analyzer Ultimate Plus", 
                              font=('Segoe UI', 18, 'bold'), fg='white', bg='#2E4057')
        title_label.place(relx=0.5, rely=0.5, anchor='center')
        
        # Subtítulo
        subtitle_label = tk.Label(canvas, text="Análisis Avanzado de Seguridad con IA y Blockchain", 
                                 font=('Segoe UI', 10), fg='#B4C6D9', bg='#2E4057')
        subtitle_label.place(relx=0.5, rely=0.8, anchor='center')
        
        # Frame de entrada con estilo moderno
        input_frame = ttk.LabelFrame(main_frame, text="💻 Código del Contrato", padding="15")
        input_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))
        input_frame.columnconfigure(0, weight=1)
        input_frame.rowconfigure(0, weight=1)
        
        # Configurar estilo para el texto
        style = ttk.Style()
        style.configure("Code.TScrolledText", 
                       background="#1E1E1E",
                       foreground="#D4D4D4",
                       fieldbackground="#1E1E1E",
                       insertbackground="#FFFFFF",
                       font=('Consolas', 11))
        
        # Text area para código
        self.code_text = scrolledtext.ScrolledText(input_frame, height=15, width=80, 
                                                   style="Code.TScrolledText",
                                                   wrap=tk.NONE)
        self.code_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configurar syntax highlighting básico
        self.code_text.tag_configure("keyword", foreground="#569CD6")
        self.code_text.tag_configure("string", foreground="#CE9178")
        self.code_text.tag_configure("comment", foreground="#6A9955")
        self.code_text.tag_configure("function", foreground="#DCDCAA")
        self.code_text.tag_configure("number", foreground="#B5CEA8")
        
        # Frame de botones con estilo moderno
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=(0, 15))
        
        # Configurar estilos de botones
        style.configure("Primary.TButton", 
                       font=('Segoe UI', 10, 'bold'),
                       foreground='white',
                       background='#048A81',
                       borderwidth=0)
        style.map("Primary.TButton",
                 background=[('active', '#05A89F'), ('pressed', '#037A73')])
        
        style.configure("Secondary.TButton", 
                       font=('Segoe UI', 10),
                       foreground='#2E4057',
                       background='#E8F4F8',
                       borderwidth=1)
        style.map("Secondary.TButton",
                 background=[('active', '#D0E8F0'), ('pressed', '#B8D8E8')])
        
        style.configure("Danger.TButton", 
                       font=('Segoe UI', 10),
                       foreground='white',
                       background='#DC3545',
                       borderwidth=0)
        style.map("Danger.TButton",
                 background=[('active', '#E85768'), ('pressed', '#C82333')])
        
        # Botones con iconos
        ttk.Button(button_frame, text="🚀 Analizar Contrato", command=self.analyze_contract, 
                  style="Primary.TButton").pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(button_frame, text="📁 Cargar Archivo", command=self.load_file, 
                  style="Secondary.TButton").pack(side=tk.LEFT, padx=8)
        ttk.Button(button_frame, text="🧹 Limpiar", command=self.clear_all, 
                  style="Danger.TButton").pack(side=tk.LEFT, padx=8)
        ttk.Button(button_frame, text="📝 Ejemplo", command=self.load_example, 
                  style="Secondary.TButton").pack(side=tk.LEFT, padx=8)
        
        # Notebook para resultados
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Tab de hallazgos con estilo moderno
        self.findings_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.findings_frame, text="🛡️ Hallazgos de Seguridad")
        self.findings_frame.columnconfigure(0, weight=1)
        self.findings_frame.rowconfigure(0, weight=1)
        
        # Configurar estilo para hallazgos
        style.configure("Findings.TScrolledText", 
                       background="#F8F9FA",
                       foreground="#212529",
                       fieldbackground="#F8F9FA",
                       font=('Segoe UI', 10))
        
        self.findings_text = scrolledtext.ScrolledText(self.findings_frame, height=15, width=80, 
                                                      style="Findings.TScrolledText")
        self.findings_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configurar tags para diferentes severidades
        self.findings_text.tag_configure("critical", foreground="#DC3545", font=('Segoe UI', 10, 'bold'))
        self.findings_text.tag_configure("high", foreground="#FD7E14", font=('Segoe UI', 10, 'bold'))
        self.findings_text.tag_configure("medium", foreground="#FFC107", font=('Segoe UI', 10, 'bold'))
        self.findings_text.tag_configure("low", foreground="#28A745", font=('Segoe UI', 10))
        self.findings_text.tag_configure("info", foreground="#17A2B8", font=('Segoe UI', 10))
        self.findings_text.tag_configure("title", foreground="#495057", font=('Segoe UI', 10, 'bold'))
        
        # Tab de ML con estilo moderno
        self.ml_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.ml_frame, text="🤖 Análisis ML")
        self.ml_frame.columnconfigure(0, weight=1)
        self.ml_frame.rowconfigure(0, weight=1)
        
        # Configurar estilo para ML
        style.configure("ML.TScrolledText", 
                       background="#F0F8FF",
                       foreground="#212529",
                       fieldbackground="#F0F8FF",
                       font=('Segoe UI', 10))
        
        self.ml_text = scrolledtext.ScrolledText(self.ml_frame, height=15, width=80, 
                                                 style="ML.TScrolledText")
        self.ml_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configurar tags para ML
        self.ml_text.tag_configure("risk_high", foreground="#DC3545", font=('Segoe UI', 10, 'bold'))
        self.ml_text.tag_configure("risk_medium", foreground="#FFC107", font=('Segoe UI', 10, 'bold'))
        self.ml_text.tag_configure("risk_low", foreground="#28A745", font=('Segoe UI', 10, 'bold'))
        self.ml_text.tag_configure("confidence", foreground="#007BFF", font=('Segoe UI', 10))
        
        # Tab de análisis comportamental
        self.behavioral_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.behavioral_frame, text="📊 Análisis Comportamental")
        self.behavioral_frame.columnconfigure(0, weight=1)
        self.behavioral_frame.rowconfigure(0, weight=1)
        
        # Configurar estilo para análisis comportamental
        style.configure("Behavioral.TScrolledText", 
                       background="#FFF8DC",
                       foreground="#212529",
                       fieldbackground="#FFF8DC",
                       font=('Segoe UI', 10))
        
        self.behavioral_text = scrolledtext.ScrolledText(self.behavioral_frame, height=15, width=80, 
                                                        style="Behavioral.TScrolledText")
        self.behavioral_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configurar tags para análisis comportamental
        self.behavioral_text.tag_configure("suspicious", foreground="#DC3545", font=('Segoe UI', 10, 'bold'))
        self.behavioral_text.tag_configure("anomaly", foreground="#FFC107", font=('Segoe UI', 10, 'bold'))
        self.behavioral_text.tag_configure("normal", foreground="#28A745", font=('Segoe UI', 10))
        
        # Status bar moderno
        status_frame = ttk.Frame(main_frame)
        status_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))
        status_frame.columnconfigure(0, weight=1)
        
        # Status bar con estilo
        style.configure("Status.TLabel", 
                       font=('Segoe UI', 9),
                       foreground='#6C757D',
                       background='#F8F9FA')
        
        self.status_var = tk.StringVar(value="🟢 Listo para analizar")
        status_bar = ttk.Label(status_frame, textvariable=self.status_var, style="Status.TLabel", 
                              relief=tk.FLAT, padding="10")
        status_bar.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        # Indicador de progreso
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(status_frame, variable=self.progress_var, 
                                           maximum=100, length=200, mode='determinate')
        self.progress_bar.grid(row=0, column=1, padx=(10, 0))
    
    def analyze_contract(self):
        """Analiza el contrato en un hilo separado con animación"""
        def analyze():
            try:
                code = self.code_text.get("1.0", tk.END).strip()
                if not code:
                    messagebox.showerror("Error", "Por favor ingrese el código del contrato")
                    return
                
                # Animación de progreso
                self.status_var.set("🔄 Analizando contrato...")
                self.progress_var.set(0)
                
                # Simular progreso
                for i in range(0, 101, 10):
                    self.progress_var.set(i)
                    self.root.update()
                    time.sleep(0.1)
                
                # Analizar
                self.status_var.set("🔍 Detectando vulnerabilidades...")
                findings = self.analyzer.analyze_code(code)
                
                self.status_var.set("🤖 Ejecutando análisis ML...")
                ml_result = self.analyzer.ml_detector.predict_risk(self.analyzer.ml_detector.extract_features(code))
                
                self.status_var.set("📊 Analizando patrones comportamentales...")
                behavioral_result = self.analyzer.behavioral_analyzer.analyze_patterns(code)
                
                # Mostrar resultados
                self.show_results(findings, ml_result, behavioral_result)
                
                self.status_var.set("✅ Análisis completado")
                self.progress_var.set(100)
                
            except Exception as e:
                messagebox.showerror("Error", f"Error al analizar: {str(e)}")
                self.status_var.set("❌ Error en el análisis")
                self.progress_var.set(0)
        
        threading.Thread(target=analyze, daemon=True).start()
    
    def show_results(self, findings: List[Finding], ml_result: MLAnalysisResult, behavioral_result: BehavioralAnalysisResult):
        """Muestra los resultados del análisis"""
        # Mostrar hallazgos
        self.findings_text.delete("1.0", tk.END)
        
        if findings:
            self.findings_text.insert(tk.END, f"Se encontraron {len(findings)} hallazgos de seguridad:\n\n")
            
            # Agrupar por severidad
            severity_groups = {}
            for finding in findings:
                if finding.severity not in severity_groups:
                    severity_groups[finding.severity] = []
                severity_groups[finding.severity].append(finding)
            
            for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
                if severity in severity_groups:
                                severity_color = severity.value.lower().replace("í", "i")
                    self.findings_text.insert(tk.END, f"\n🚨 {severity.value}:\n", severity_color)
                    for finding in severity_groups[severity]:
                        self.findings_text.insert(tk.END, f"\n  🔴 {finding.title}\n", "title")
                        self.findings_text.insert(tk.END, f"  📍 Línea: {finding.line_number}\n")
                        if finding.code_snippet:
                            self.findings_text.insert(tk.END, f"  💻 Código: {finding.code_snippet}\n")
                        self.findings_text.insert(tk.END, f"  📝 Descripción: {finding.description}\n")
                        if finding.recommendation:
                            self.findings_text.insert(tk.END, f"  💡 Recomendación: {finding.recommendation}\n")
                        self.findings_text.insert(tk.END, "─" * 60 + "\n")
        else:
            self.findings_text.insert(tk.END, "No se encontraron vulnerabilidades críticas.\n")
        
        # Mostrar resultados ML con estilo
        self.ml_text.delete("1.0", tk.END)
        self.ml_text.insert(tk.END, "🤖 Análisis de Machine Learning\n\n")
        
        # Risk Score con color
        risk_score = ml_result.risk_score
        risk_tag = "risk_high" if risk_score > 0.7 else "risk_medium" if risk_score > 0.4 else "risk_low"
        self.ml_text.insert(tk.END, f"📊 Risk Score: {risk_score:.2%}\n", risk_tag)
        
        self.ml_text.insert(tk.END, f"🎯 Confidence: {ml_result.confidence:.2%}\n", "confidence")
        if ml_result.scam_type:
            self.ml_text.insert(tk.END, f"⚠️ Scam Type: {ml_result.scam_type.value}\n")
        self.ml_text.insert(tk.END, f"\n📋 {ml_result.explanation}\n")
        
        # Mostrar análisis comportamental con estilo
        self.behavioral_text.delete("1.0", tk.END)
        self.behavioral_text.insert(tk.END, "📊 Análisis Comportamental\n\n")
        
        # Transaction Risk con color
        tx_risk = behavioral_result.transaction_risk
        risk_tag = "suspicious" if tx_risk > 0.7 else "anomaly" if tx_risk > 0.4 else "normal"
        self.behavioral_text.insert(tk.END, f"💸 Transaction Risk: {tx_risk:.2%}\n\n", risk_tag)
        
        if behavioral_result.suspicious_patterns:
            self.behavioral_text.insert(tk.END, "🔍 Patrones Sospechosos:\n", "suspicious")
            for pattern in behavioral_result.suspicious_patterns:
                self.behavioral_text.insert(tk.END, f"  ⚠️ {pattern}\n")
        
        if behavioral_result.gas_anomalies:
            self.behavioral_text.insert(tk.END, "\n⛽ Anomalías de Gas:\n", "anomaly")
            for anomaly in behavioral_result.gas_anomalies:
                self.behavioral_text.insert(tk.END, f"  📈 {anomaly}\n")
        
        if behavioral_result.timing_anomalies:
            self.behavioral_text.insert(tk.END, "\nAnomalías de Timing:\n")
            for anomaly in behavioral_result.timing_anomalies:
                self.behavioral_text.insert(tk.END, f"  - {anomaly}\n")
        
        self.status_var.set(f"Análisis completado - {len(findings)} hallazgos encontrados")
    
    def _show_error(self, error_message: str):
        """Muestra mensaje de error"""
        messagebox.showerror("Error", error_message)
        self.status_var.set("Error en el análisis")
    
    def load_file(self):
        """Carga código desde archivo"""
        file_path = filedialog.askopenfilename(
            title="Seleccionar archivo de contrato",
            filetypes=[("Solidity files", "*.sol"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read()
                    self.code_text.delete("1.0", tk.END)
                    self.code_text.insert("1.0", content)
                    self.status_var.set(f"Archivo cargado: {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo cargar el archivo: {str(e)}")
    
    def clear_all(self):
        """Limpia todo el contenido"""
        self.code_text.delete("1.0", tk.END)
        self.findings_text.delete("1.0", tk.END)
        self.ml_text.delete("1.0", tk.END)
        self.behavioral_text.delete("1.0", tk.END)
        self.status_var.set("🟢 Listo para analizar")
        self.progress_var.set(0)
    
    def load_example(self):
        """Carga un ejemplo de contrato vulnerable"""
        example_code = '''// Smart Contract Vulnerable Example
pragma solidity ^0.8.0;

contract VulnerableContract {
    address public owner;
    mapping(address => uint) public balances;
    mapping(address => bool) public blacklisted;
    
    event Transfer(address indexed from, address indexed to, uint value);
    
    constructor() {
        owner = msg.sender;
    }
    
    // Vulnerabilidad: Reentrancy
    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;
    }
    
    // Vulnerabilidad: Unlimited mint
    function mint(address to, uint amount) public {
        require(msg.sender == owner, "Only owner");
        balances[to] += amount;
    }
    
    // Vulnerabilidad: Blacklist
    function addToBlacklist(address account) public {
        require(msg.sender == owner, "Only owner");
        blacklisted[account] = true;
    }
    
    // Vulnerabilidad: Honeypot
    function transfer(address to, uint amount) public returns (bool) {
        require(!blacklisted[msg.sender], "Blacklisted");
        require(balances[msg.sender] >= amount);
        require(msg.value == 0, "No ETH allowed"); // Honeypot pattern
        
        balances[msg.sender] -= amount;
        balances[to] += amount;
        
        emit Transfer(msg.sender, to, amount);
        return true;
    }
    
    // Vulnerabilidad: Backdoor
    function emergencyWithdraw() public {
        require(msg.sender == owner || block.timestamp > 1640995200, "Emergency only");
        (bool success, ) = owner.call{value: address(this).balance}("");
        require(success, "Transfer failed");
    }
}'''
        
        self.code_text.delete("1.0", tk.END)
        self.code_text.insert("1.0", example_code)
        self.status_var.set("📝 Ejemplo de contrato vulnerable cargado")
        
        # Aplicar syntax highlighting básico
        self._apply_syntax_highlighting()
    
    def _interpolate_color(self, color1: str, color2: str, factor: float) -> str:
        """Interpola entre dos colores"""
        # Convert hex to RGB
        r1, g1, b1 = int(color1[1:3], 16), int(color1[3:5], 16), int(color1[5:7], 16)
        r2, g2, b2 = int(color2[1:3], 16), int(color2[3:5], 16), int(color2[5:7], 16)
        
        # Interpolate
        r = int(r1 + (r2 - r1) * factor)
        g = int(g1 + (g2 - g1) * factor)
        b = int(b1 + (b2 - b1) * factor)
        
        # Convert back to hex
        return f"#{r:02x}{g:02x}{b:02x}"
    
    def _apply_syntax_highlighting(self):
        """Aplica resaltado de sintaxis básico"""
        content = self.code_text.get("1.0", tk.END)
        
        # Palabras clave de Solidity
        keywords = ["pragma", "contract", "function", "public", "private", "internal", "external", 
                    "view", "pure", "payable", "returns", "require", "assert", "revert", "emit",
                    "event", "modifier", "constructor", "mapping", "address", "uint", "int", 
                    "bool", "string", "bytes", "struct", "enum", "library", "interface", "import",
                    "if", "else", "for", "while", "do", "break", "continue", "return", "throw",
                    "memory", "storage", "calldata", "new", "delete", "this", "super", "msg", 
                    "block", "tx", "selfdestruct", "suicide"]
        
        # Aplicar highlighting a palabras clave
        for keyword in keywords:
            start_idx = "1.0"
            while True:
                pos = self.code_text.search(f"\\b{keyword}\\b", start_idx, tk.END, regexp=True)
                if not pos:
                    break
                end_pos = f"{pos}+{len(keyword)}c"
                self.code_text.tag_add("keyword", pos, end_pos)
                start_idx = end_pos
        
        # Aplicar highlighting a strings
        start_idx = "1.0"
        in_string = False
        string_start = None
        
        for i, char in enumerate(content):
            if char == '"' and not in_string:
                in_string = True
                string_start = i
            elif char == '"' and in_string:
                in_string = False
                start_pos = f"1.0+{string_start}c"
                end_pos = f"1.0+{i+1}c"
                self.code_text.tag_add("string", start_pos, end_pos)
        
        # Aplicar highlighting a comentarios
        lines = content.split('\n')
        for line_num, line in enumerate(lines):
            if '//' in line:
                comment_start = line.index('//')
                start_pos = f"{line_num + 1}.{comment_start}"
                end_pos = f"{line_num + 1}.end"
                self.code_text.tag_add("comment", start_pos, end_pos)

def main():
    """Función principal"""
    root = tk.Tk()
    app = SmartContractAnalyzerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
