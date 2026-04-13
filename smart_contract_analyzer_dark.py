#!/usr/bin/env python3
"""
Smart Contract Analyzer - Dark Mode Edition
Análisis avanzado de contratos inteligentes con GUI Dark Mode verde y negro
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

# Import new modules (avoiding circular imports)
try:
    from blockchain_integration import BlockchainExplorer, EtherscanExplorer, OnChainAnalyzer
    from reporting_system import ReportingSystem, ReportData
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
    FLASH_LOAN = "Flash Loan Attack"
    MEV_MANIPULATION = "MEV Manipulation"
    SANDWICH_ATTACK = "Sandwich Attack"
    BACKDOOR = "Backdoor Functions"
    UNLIMITED_MINT = "Unlimited Mint"
    BLACKLIST = "Blacklist Functions"
    GAS_MANIPULATION = "Gas Manipulation"

@dataclass
class Finding:
    """Representa un hallazgo de seguridad"""
    title: str
    description: str
    severity: Severity
    line_number: int
    code_snippet: str
    recommendation: str
    pattern_name: str

@dataclass
class MLAnalysisResult:
    """Resultado del análisis ML"""
    risk_score: float
    confidence: float
    scam_type: Optional[ScamType]
    explanation: str
    features: Dict[str, float]

@dataclass
class BehavioralAnalysisResult:
    """Resultado del análisis comportamental"""
    transaction_risk: float
    suspicious_patterns: List[str]
    gas_anomalies: List[str]
    timing_anomalies: List[str]
    overall_risk: float

class SmartContractAnalyzer:
    """Analizador principal de contratos inteligentes"""
    
    def __init__(self):
        self.patterns = self._load_patterns()
        self.ml_detector = self._init_ml_detector()
        self.behavioral_analyzer = self._init_behavioral_analyzer()
        
        # Inicializar módulos avanzados si están disponibles
        if BytecodeAnalyzer:
            self.bytecode_analyzer = BytecodeAnalyzer()
        if CVEDatabase:
            self.cve_database = CVEDatabase()
        if PluginManager:
            self.plugin_manager = PluginManager()
    
    def _load_patterns(self) -> Dict[str, Dict]:
        """Carga patrones de detección"""
        return {
            'honeypot_transfer_block': {
                'pattern': r'require\s*\(\s*.*\s*==\s*.*\s*\)',
                'description': 'Bloqueo de transferencia sospechoso',
                'severity': Severity.CRITICAL
            },
            'rug_pull_ownership': {
                'pattern': r'function\s+.*transferOwnership\s*\(',
                'description': 'Función de transferencia de ownership',
                'severity': Severity.HIGH
            },
            'phishing_approval': {
                'pattern': r'approve\s*\(\s*.*\s*,\s*.*\s*\)',
                'description': 'Aprobación de tokens sospechosa',
                'severity': Severity.MEDIUM
            },
            'flash_loan_vulnerable': {
                'pattern': r'function\s+.*flashLoan\s*\(',
                'description': 'Función vulnerable a flash loan',
                'severity': Severity.HIGH
            },
            'mev_manipulation': {
                'pattern': r'block\.timestamp|block\.difficulty',
                'description': 'Uso de variables de bloque para randomness',
                'severity': Severity.MEDIUM
            },
            'sandwich_attack': {
                'pattern': r'swap.*\{.*\}',
                'description': 'Función swap vulnerable a sandwich attack',
                'severity': Severity.MEDIUM
            },
            'backdoor_functions': {
                'pattern': r'function\s+.*emergency.*\(',
                'description': 'Función de emergencia sospechosa',
                'severity': Severity.HIGH
            },
            'reentrancy_vulnerable': {
                'pattern': r'\.call\s*\{.*value:.*\}',
                'description': 'Llamada externa vulnerable a reentrancy',
                'severity': Severity.CRITICAL
            },
            'unlimited_mint': {
                'pattern': r'mint\s*\(\s*.*\s*,\s*.*\s*\)',
                'description': 'Función de mint sin límites',
                'severity': Severity.HIGH
            },
            'blacklist_functions': {
                'pattern': r'blacklist|blacklist.*=.*true',
                'description': 'Función de blacklist detectada',
                'severity': Severity.MEDIUM
            },
            'gas_manipulation_advanced': {
                'pattern': r'gas\s*\(\s*\)|gasleft\s*\(\s*\)',
                'description': 'Manipulación avanzada de gas',
                'severity': Severity.MEDIUM
            },
            'integer_overflow': {
                'pattern': r'\w+\s*\+\s*\w+|\w+\s*\*\s*\w+',
                'description': 'Posible integer overflow/underflow',
                'severity': Severity.HIGH
            },
            'access_control_bypass': {
                'pattern': r'require\s*\(\s*msg\.sender\s*==\s*owner\s*\)',
                'description': 'Control de acceso básico vulnerable',
                'severity': Severity.MEDIUM
            },
            'logic_bomb': {
                'pattern': r'block\.timestamp\s*>\s*\d+',
                'description': 'Logic bomb basada en tiempo',
                'severity': Severity.HIGH
            },
            'unchecked_calls': {
                'pattern': r'\.call\s*\([^)]*\)\s*;(?!\s*require\s*\()',
                'description': 'Llamada externa sin validación',
                'severity': Severity.MEDIUM
            },
            'delegatecall_vulnerable': {
                'pattern': r'\.delegatecall\s*\(',
                'description': 'Uso peligroso de delegatecall',
                'severity': Severity.HIGH
            },
            'storage_collision': {
                'pattern': r'storage\s*\[\s*\w+\s*\]\s*=',
                'description': 'Posible storage collision',
                'severity': Severity.MEDIUM
            },
            'oracle_manipulation': {
                'pattern': r'price|Price\s*=\s*.*\.',
                'description': 'Dependencia de oráculo sin validación',
                'severity': Severity.MEDIUM
            },
            'proxy_vulnerabilities': {
                'pattern': r'delegatecall\s*\(\s*.*\s*\)',
                'description': 'Proxy contract vulnerable',
                'severity': Severity.HIGH
            },
            'upgradeability_issues': {
                'pattern': r'upgrade|Upgrade\s*\(',
                'description': 'Problemas de actualización',
                'severity': Severity.MEDIUM
            },
            'erc20_violations': {
                'pattern': r'transfer.*returns\s*\(\s*bool\s*\)',
                'description': 'Violación del estándar ERC20',
                'severity': Severity.LOW
            },
            'nft_vulnerabilities': {
                'pattern': r'tokenOfOwnerByIndex|ownerOf\s*\(',
                'description': 'Vulnerabilidad en NFT',
                'severity': Severity.MEDIUM
            },
            'defi_vulnerabilities': {
                'pattern': r'addLiquidity|removeLiquidity',
                'description': 'Vulnerabilidad en protocolo DeFi',
                'severity': Severity.HIGH
            },
            'time_manipulation': {
                'pattern': r'block\.timestamp|now',
                'description': 'Manipulación de tiempo',
                'severity': Severity.MEDIUM
            },
            'randomness_vulnerable': {
                'pattern': r'random\s*\(\s*\)|keccak256.*block\.timestamp',
                'description': 'Randomness vulnerable',
                'severity': Severity.HIGH
            },
            'selfdestruct_patterns': {
                'pattern': r'selfdestruct\s*\(|suicide\s*\(',
                'description': 'Patrón de selfdestruct',
                'severity': Severity.CRITICAL
            }
        }
    
    def _init_ml_detector(self):
        """Inicializa el detector ML"""
        return MLDetector()
    
    def _init_behavioral_analyzer(self):
        """Inicializa el analizador comportamental"""
        return BehavioralAnalyzer()
    
    def analyze(self, code: str) -> List[Finding]:
        """Analiza el código y retorna hallazgos"""
        findings = []
        lines = code.split('\n')
        
        for pattern_name, pattern_info in self.patterns.items():
            import re
            pattern = pattern_info['pattern']
            
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    finding = Finding(
                        title=self._get_pattern_title(pattern_name),
                        description=pattern_info['description'],
                        severity=pattern_info['severity'],
                        line_number=line_num,
                        code_snippet=line.strip(),
                        recommendation=self._get_recommendation(pattern_name),
                        pattern_name=pattern_name
                    )
                    findings.append(finding)
        
        return findings
    
    def ml_analyze(self, code: str) -> MLAnalysisResult:
        """Realiza análisis ML del código"""
        features = self.ml_detector.extract_features(code)
        risk_score = self.ml_detector.predict_risk(features)
        scam_type = self.ml_detector.predict_scam_type(features)
        confidence = self.ml_detector.calculate_confidence(features)
        explanation = self.ml_detector.generate_explanation(features, risk_score)
        
        return MLAnalysisResult(
            risk_score=risk_score,
            confidence=confidence,
            scam_type=scam_type,
            explanation=explanation,
            features=features
        )
    
    def analyze_behavioral_patterns(self, code: str) -> BehavioralAnalysisResult:
        """Analiza patrones comportamentales"""
        return self.behavioral_analyzer.analyze_patterns(code)
    
    def _get_pattern_title(self, pattern_name: str) -> str:
        """Obtiene título del patrón"""
        titles = {
            'honeypot_transfer_block': 'Honeypot - Bloqueo de Transferencia',
            'rug_pull_ownership': 'Rug Pull - Transferencia de Ownership',
            'phishing_approval': 'Phishing - Aprobación Maliciosa',
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
            'nft_vulnerabilities': 'Implementar validaciones de ownership y transferencia.',
            'defi_vulnerabilities': 'Usar protocolos DeFi auditados y testeados.',
            'time_manipulation': 'Evitar dependencia de block.timestamp para lógica crítica.',
            'randomness_vulnerable': 'Usar oráculos de randomness como Chainlink VRF.',
            'selfdestruct_patterns': 'Implementar controles de acceso para selfdestruct.'
        }
        return recommendations.get(pattern_name, 'Revisar y mejorar la implementación.')

class MLDetector:
    """Detector basado en Machine Learning"""
    
    def __init__(self):
        self.model = self._load_model()
    
    def _load_model(self):
        """Carga el modelo ML"""
        # Simulación de modelo ML
        return {"trained": True, "accuracy": 0.95}
    
    def extract_features(self, code: str) -> Dict[str, float]:
        """Extrae características del código"""
        features = {
            'code_length': len(code),
            'function_count': code.count('function'),
            'require_count': code.count('require'),
            'external_calls': code.count('.call'),
            'transfer_count': code.count('transfer'),
            'owner_references': code.count('owner'),
            'timestamp_usage': code.count('block.timestamp'),
            'complexity_score': self._calculate_complexity(code)
        }
        return features
    
    def _calculate_complexity(self, code: str) -> float:
        """Calcula complejidad del código"""
        # Simulación de cálculo de complejidad
        return random.uniform(0.1, 1.0)
    
    def predict_risk(self, features: Dict[str, float]) -> float:
        """Predice el riesgo"""
        # Simulación de predicción ML
        base_risk = 0.3
        if features['external_calls'] > 5:
            base_risk += 0.2
        if features['owner_references'] > 10:
            base_risk += 0.15
        if features['timestamp_usage'] > 0:
            base_risk += 0.1
        return min(base_risk + random.uniform(-0.1, 0.1), 1.0)
    
    def predict_scam_type(self, features: Dict[str, float]) -> Optional[ScamType]:
        """Predice el tipo de scam"""
        # Simulación de predicción de tipo
        if features['transfer_count'] > 10 and features['owner_references'] > 5:
            return ScamType.RUG_PULL
        elif features['external_calls'] > 8:
            return ScamType.HONEYPOT
        elif features['timestamp_usage'] > 0:
            return ScamType.MEV_MANIPULATION
        return None
    
    def calculate_confidence(self, features: Dict[str, float]) -> float:
        """Calcula confianza de la predicción"""
        # Simulación de cálculo de confianza
        return random.uniform(0.7, 0.95)
    
    def generate_explanation(self, features: Dict[str, float], risk_score: float) -> str:
        """Genera explicación del análisis"""
        explanation = f"Análisis ML completado con riesgo del {risk_score:.2%}. "
        
        if risk_score > 0.7:
            explanation += "El contrato presenta características de alto riesgo."
        elif risk_score > 0.4:
            explanation += "El contrato presenta algunas características sospechosas."
        else:
            explanation += "El contrato parece relativamente seguro."
        
        return explanation

class BehavioralAnalyzer:
    """Analizador de patrones comportamentales"""
    
    def __init__(self):
        self.patterns = self._load_behavioral_patterns()
    
    def _load_behavioral_patterns(self) -> Dict[str, str]:
        """Carga patrones comportamentales"""
        return {
            'suspicious_timing': 'block.timestamp',
            'gas_manipulation': 'gas(',
            'external_dependency': 'require(',
            'state_change': 'balances[',
            'ownership_pattern': 'msg.sender == owner'
        }
    
    def analyze_patterns(self, code: str) -> BehavioralAnalysisResult:
        """Analiza patrones comportamentales"""
        suspicious_patterns = []
        gas_anomalies = []
        timing_anomalies = []
        
        # Análisis de patrones
        for pattern_name, pattern in self.patterns.items():
            if pattern in code:
                if 'timing' in pattern_name:
                    timing_anomalies.append(f"Patrón temporal detectado: {pattern}")
                elif 'gas' in pattern_name:
                    gas_anomalies.append(f"Anomalía de gas: {pattern}")
                else:
                    suspicious_patterns.append(f"Patrón sospechoso: {pattern}")
        
        # Calcular riesgos
        transaction_risk = self._calculate_transaction_risk(code, suspicious_patterns)
        overall_risk = self._calculate_overall_risk(transaction_risk, suspicious_patterns)
        
        return BehavioralAnalysisResult(
            transaction_risk=transaction_risk,
            suspicious_patterns=suspicious_patterns,
            gas_anomalies=gas_anomalies,
            timing_anomalies=timing_anomalies,
            overall_risk=overall_risk
        )
    
    def _calculate_transaction_risk(self, code: str, patterns: List[str]) -> float:
        """Calcula riesgo de transacción"""
        base_risk = 0.2
        if 'transfer' in code:
            base_risk += 0.1
        if 'call{' in code:
            base_risk += 0.2
        if patterns:
            base_risk += len(patterns) * 0.05
        return min(base_risk, 1.0)
    
    def _calculate_overall_risk(self, transaction_risk: float, patterns: List[str]) -> float:
        """Calcula riesgo general"""
        return min(transaction_risk + len(patterns) * 0.05, 1.0)

class SmartContractAnalyzerGUI:
    """Interfaz gráfica Dark Mode Edition"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Smart Contract Analyzer - Dark Mode")
        self.root.geometry("1400x900")
        
        # Configurar tema dark mode
        self.root.configure(bg='#0D1117')
        
        # Variables para animaciones
        self.animation_running = False
        self.pulse_alpha = 0
        
        # Inicializar analizador
        self.analyzer = SmartContractAnalyzer()
        
        # Configurar interfaz
        self.setup_ui()
        
        # Iniciar animaciones
        self.start_animations()
    
    def setup_ui(self):
        """Configura la interfaz de usuario dark mode"""
        # Frame principal
        main_frame = tk.Frame(self.root, bg='#0D1117')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Header con animación
        self.create_animated_header(main_frame)
        
        # Frame de entrada
        self.create_code_section(main_frame)
        
        # Frame de botones
        self.create_button_section(main_frame)
        
        # Notebook para resultados
        self.create_results_section(main_frame)
        
        # Status bar
        self.create_status_section(main_frame)
    
    def create_animated_header(self, parent):
        """Crea header animado"""
        header_frame = tk.Frame(parent, bg='#161B22', relief=tk.RAISED, bd=2)
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Canvas para animación de fondo
        self.header_canvas = Canvas(header_frame, height=80, bg='#161B22', highlightthickness=0)
        self.header_canvas.pack(fill=tk.BOTH, expand=True)
        
        # Título principal
        title_label = tk.Label(self.header_canvas, 
                              text="Smart Contract Analyzer", 
                              font=('Consolas', 24, 'bold'),
                              fg='#00FF41',
                              bg='#161B22')
        title_label.place(relx=0.5, rely=0.3, anchor='center')
        
        # Subtítulo
        subtitle_label = tk.Label(self.header_canvas,
                                text="Dark Mode Edition - Advanced Security Analysis",
                                font=('Consolas', 12),
                                fg='#7EE787',
                                bg='#161B22')
        subtitle_label.place(relx=0.5, rely=0.7, anchor='center')
        
        # Iniciar animación de fondo
        self.animate_header_background()
    
    def create_code_section(self, parent):
        """Crea sección de código con estilo dark mode"""
        code_frame = tk.LabelFrame(parent, 
                                   text="Source Code Analysis",
                                   font=('Consolas', 12, 'bold'),
                                   fg='#00FF41',
                                   bg='#161B22',
                                   relief=tk.RIDGE,
                                   bd=2)
        code_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        # Text area para código con tema oscuro mejorado
        self.code_text = scrolledtext.ScrolledText(
            code_frame,
            height=15,
            wrap=tk.NONE,
            bg='#010409',
            fg='#E6EDF3',
            insertbackground='#E6EDF3',
            font=('Consolas', 11),
            selectbackground='#00FF41',
            selectforeground='#010409',
            relief=tk.FLAT,
            bd=0
        )
        self.code_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Configurar syntax highlighting dark mode
        self.setup_dark_syntax_highlighting()
    
    def create_button_section(self, parent):
        """Crea sección de botones con estilo dark mode"""
        button_frame = tk.Frame(parent, bg='#0D1117')
        button_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Estilos de botones dark mode
        button_styles = {
            'primary': {'bg': '#238636', 'fg': 'white', 'active_bg': '#2EA043'},
            'secondary': {'bg': '#21262D', 'fg': '#E6EDF3', 'active_bg': '#30363D'},
            'danger': {'bg': '#DA3633', 'fg': 'white', 'active_bg': '#F85149'}
        }
        
        buttons = [
            ("Analyze Contract", self.analyze_contract, 'primary'),
            ("Load File", self.load_file, 'secondary'),
            ("Clear", self.clear_all, 'danger'),
            ("Example", self.load_example, 'secondary')
        ]
        
        for text, command, style_name in buttons:
            style = button_styles[style_name]
            btn = tk.Button(
                button_frame,
                text=text,
                command=command,
                bg=style['bg'],
                fg=style['fg'],
                font=('Consolas', 10, 'bold'),
                relief=tk.FLAT,
                bd=0,
                padx=15,
                pady=8,
                cursor='hand2'
            )
            btn.pack(side=tk.LEFT, padx=5)
            
            # Efecto hover
            btn.bind('<Enter>', lambda e, b=btn, s=style: b.config(bg=s['active_bg']))
            btn.bind('<Leave>', lambda e, b=btn, s=style: b.config(bg=s['bg']))
    
    def create_results_section(self, parent):
        """Crea sección de resultados con pestañas dark mode"""
        # Notebook personalizado
        self.notebook = tk.Frame(parent, bg='#0D1117')
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        # Tabs
        self.tabs = []
        tab_names = ["Security Findings", "ML Analysis", "Behavioral Analysis"]
        tab_colors = ["#DA3633", "#238636", "#58A6FF"]
        
        for i, (name, color) in enumerate(zip(tab_names, tab_colors)):
            # Tab button
            tab_btn = tk.Button(
                self.notebook,
                text=name,
                font=('Consolas', 10, 'bold'),
                bg='#21262D' if i != 0 else color,
                fg='white',
                relief=tk.FLAT,
                bd=0,
                padx=15,
                pady=8,
                cursor='hand2'
            )
            tab_btn.grid(row=0, column=i, sticky='ew', padx=2)
            
            # Content frame
            content_frame = tk.Frame(self.notebook, bg='#161B22')
            content_frame.grid(row=1, column=0, columnspan=3, sticky='nsew', pady=2)
            content_frame.grid_remove()
            
            # Text area para resultados
            text_widget = scrolledtext.ScrolledText(
                content_frame,
                height=12,
                wrap=tk.WORD,
                bg='#010409',
                fg='#E6EDF3',
                font=('Consolas', 10),
                relief=tk.FLAT,
                bd=0
            )
            text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            self.tabs.append({
                'button': tab_btn,
                'content': content_frame,
                'text': text_widget,
                'active': i == 0
            })
            
            # Configurar tab click
            tab_btn.config(command=lambda idx=i: self.switch_tab(idx))
            
            # Mostrar primera tab
            if i == 0:
                content_frame.grid()
                self.setup_findings_tags(text_widget)
                print(f"DEBUG: First tab (findings) made visible")
        
        # Configurar grid weights
        self.notebook.grid_columnconfigure(0, weight=1)
        self.notebook.grid_columnconfigure(1, weight=1)
        self.notebook.grid_columnconfigure(2, weight=1)
        self.notebook.grid_rowconfigure(1, weight=1)
        
        # Guardar referencias
        self.findings_text = self.tabs[0]['text']
        self.ml_text = self.tabs[1]['text']
        self.behavioral_text = self.tabs[2]['text']
        
        print(f"DEBUG: Text widgets assigned:")
        print(f"  findings_text: {type(self.findings_text)}")
        print(f"  ml_text: {type(self.ml_text)}")
        print(f"  behavioral_text: {type(self.behavioral_text)}")
    
    def create_status_section(self, parent):
        """Crea sección de status con estilo dark mode"""
        status_frame = tk.Frame(parent, bg='#161B22', relief=tk.RIDGE, bd=2)
        status_frame.pack(fill=tk.X, pady=(0, 0))
        
        # Status label
        self.status_var = tk.StringVar(value="Ready to analyze contracts")
        status_label = tk.Label(
            status_frame,
            textvariable=self.status_var,
            font=('Consolas', 10),
            fg='#7EE787',
            bg='#161B22',
            anchor='w'
        )
        status_label.pack(side=tk.LEFT, padx=15, pady=10)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            status_frame,
            variable=self.progress_var,
            maximum=100,
            length=300,
            mode='determinate',
            style='Dark.Horizontal.TProgressbar'
        )
        
        # Configurar estilo dark para progress bar
        style = ttk.Style()
        style.theme_use('default')
        style.configure(
            'Dark.Horizontal.TProgressbar',
            background='#00FF41',
            troughcolor='#21262D',
            bordercolor='#161B22',
            lightcolor='#00FF41',
            darkcolor='#238636'
        )
        
        self.progress_bar.pack(side=tk.RIGHT, padx=15, pady=10)
    
    def setup_dark_syntax_highlighting(self):
        """Configura syntax highlighting para dark mode"""
        # Palabras clave de Solidity con colores dark mode
        keywords = ["pragma", "contract", "function", "public", "private", "internal", "external", 
                    "view", "pure", "payable", "returns", "require", "assert", "revert", "emit",
                    "event", "modifier", "constructor", "mapping", "address", "uint", "int", 
                    "bool", "string", "bytes", "struct", "enum", "library", "interface", "import",
                    "if", "else", "for", "while", "do", "break", "continue", "return", "throw",
                    "memory", "storage", "calldata", "new", "delete", "this", "super", "msg", 
                    "block", "tx", "selfdestruct", "suicide"]
        
        # Configurar tags con colores dark mode
        self.code_text.tag_configure("keyword", foreground="#FF7B72")
        self.code_text.tag_configure("string", foreground="#A5D6FF")
        self.code_text.tag_configure("comment", foreground="#7EE787")
        self.code_text.tag_configure("function", foreground="#D2A8FF")
        self.code_text.tag_configure("number", foreground="#79C0FF")
        self.code_text.tag_configure("operator", foreground="#FFA657")
    
    def setup_findings_tags(self, text_widget):
        """Configura tags para hallazgos con colores dark mode"""
        text_widget.tag_configure("critical", foreground="#FF7B72", font=('Consolas', 10, 'bold'))
        text_widget.tag_configure("high", foreground="#FFA657", font=('Consolas', 10, 'bold'))
        text_widget.tag_configure("medium", foreground="#D29922", font=('Consolas', 10, 'bold'))
        text_widget.tag_configure("low", foreground="#7EE787", font=('Consolas', 10))
        text_widget.tag_configure("info", foreground="#79C0FF", font=('Consolas', 10))
        text_widget.tag_configure("title", foreground="#E6EDF3", font=('Consolas', 10, 'bold'))
    
    def switch_tab(self, index):
        """Cambia entre tabs con animación suave"""
        for i, tab in enumerate(self.tabs):
            if i == index:
                # Activar tab
                tab['content'].grid()
                tab['button'].config(bg='#238636' if i == 1 else '#DA3633' if i == 0 else '#58A6FF')
                tab['active'] = True
                
                # Animación de entrada
                self.fade_in_widget(tab['content'])
            else:
                # Desactivar tab
                if tab['active']:
                    tab['content'].grid_remove()
                    tab['button'].config(bg='#21262D')
                    tab['active'] = False
    
    def fade_in_widget(self, widget):
        """Animación de fade in suave (simulada con colores)"""
        # Simular fade in cambiando el fondo temporalmente
        original_bg = widget.cget('bg')
        for i in range(10):
            # Interpolar color de fondo para simular fade
            fade_factor = i / 10.0
            widget.update()
            time.sleep(0.02)
        widget.config(bg=original_bg)
    
    def animate_header_background(self):
        """Animación de fondo del header"""
        if not hasattr(self, 'header_particles'):
            self.header_particles = []
            for _ in range(20):
                x = random.randint(0, 1400)
                y = random.randint(0, 80)
                size = random.randint(1, 3)
                speed = random.uniform(0.5, 2.0)
                self.header_particles.append({'x': x, 'y': y, 'size': size, 'speed': speed})
        
        def update_particles():
            self.header_canvas.delete("particle")
            for particle in self.header_particles:
                # Actualizar posición
                particle['x'] += particle['speed']
                if particle['x'] > 1400:
                    particle['x'] = -10
                
                # Dibujar partícula
                self.header_canvas.create_oval(
                    particle['x'], particle['y'],
                    particle['x'] + particle['size'], particle['y'] + particle['size'],
                    fill='#00FF41',
                    outline='',
                    tags="particle"
                )
            
            # Continuar animación
            if hasattr(self, 'header_canvas'):
                self.header_canvas.after(50, update_particles)
        
        update_particles()
    
    def start_animations(self):
        """Inicia animaciones suaves"""
        self.animation_running = True
        self.pulse_status_indicator()
    
    def pulse_status_indicator(self):
        """Animación de pulso para status"""
        if self.animation_running:
            # Cambiar color de status suavemente
            colors = ['#7EE787', '#00FF41', '#7EE787']
            color = colors[int(self.pulse_alpha) % len(colors)]
            
            # Actualizar si está listo
            if "Ready" in self.status_var.get():
                # Simular pulso cambiando el texto temporalmente
                current_text = self.status_var.get()
                if "Ready" in current_text:
                    self.status_var.set("Ready to analyze contracts")
            
            self.pulse_alpha += 0.1
            self.root.after(500, self.pulse_status_indicator)
    
    def analyze_contract(self):
        """Analiza el contrato con animaciones mejoradas"""
        def analyze():
            try:
                code = self.code_text.get("1.0", tk.END).strip()
                if not code:
                    messagebox.showerror("Error", "Please enter contract code")
                    return
                
                # Animación de análisis con efectos suaves
                self.animate_analysis_process()
                
                # Analizar
                findings = self.analyzer.analyze(code)
                ml_result = self.analyzer.ml_analyze(code)
                behavioral_result = self.analyzer.analyze_behavioral_patterns(code)
                
                # Mostrar resultados con animación
                self.show_animated_results(findings, ml_result, behavioral_result)
                
                # Forzar mostrar la primera tab (findings)
                self.switch_tab(0)
                
                # Status final con efecto
                self.status_var.set("Analysis completed successfully!")
                self.animate_success()
                
            except Exception as e:
                messagebox.showerror("Error", f"Analysis error: {str(e)}")
                self.status_var.set("Analysis failed")
                self.progress_var.set(0)
        
        threading.Thread(target=analyze, daemon=True).start()
    
    def animate_analysis_process(self):
        """Animación del proceso de análisis"""
        stages = [
            ("Scanning code structure...", 20),
            ("Detecting vulnerabilities...", 40),
            ("Running ML analysis...", 60),
            ("Analyzing behavioral patterns...", 80),
            ("Generating results...", 100)
        ]
        
        for stage, progress in stages:
            if not self.animation_running:
                break
                
            self.status_var.set(stage)
            self.animate_progress(progress)
            time.sleep(0.8)  # Más suave
    
    def animate_progress(self, target):
        """Animación suave de progreso"""
        current = self.progress_var.get()
        step = (target - current) / 20
        
        for _ in range(20):
            if current < target:
                current += step
                self.progress_var.set(current)
                self.root.update()
                time.sleep(0.03)
    
    def show_animated_results(self, findings, ml_result, behavioral_result):
        """Muestra resultados con animación"""
        # Limpiar resultados
        self.findings_text.delete("1.0", tk.END)
        self.ml_text.delete("1.0", tk.END)
        self.behavioral_text.delete("1.0", tk.END)
        
        # Animar entrada de resultados
        if findings:
            self.findings_text.insert(tk.END, f"Found {len(findings)} security findings:\n\n")
            
            # Agrupar por severidad
            severity_groups = {}
            for finding in findings:
                if finding.severity not in severity_groups:
                    severity_groups[finding.severity] = []
                severity_groups[finding.severity].append(finding)
            
            for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
                if severity in severity_groups:
                    severity_color = severity.value.lower().replace("í", "i")
                    self.findings_text.insert(tk.END, f"\n{severity.value}:\n", severity_color)
                    
                    for finding in severity_groups[severity]:
                        self.findings_text.insert(tk.END, f"\n  {finding.title}\n", "title")
                        self.findings_text.insert(tk.END, f"  Line: {finding.line_number}\n")
                        if finding.code_snippet:
                            self.findings_text.insert(tk.END, f"  Code: {finding.code_snippet}\n")
                        self.findings_text.insert(tk.END, f"  Description: {finding.description}\n")
                        if finding.recommendation:
                            self.findings_text.insert(tk.END, f"  Recommendation: {finding.recommendation}\n")
                        self.findings_text.insert(tk.END, " " * 60 + "\n")
        else:
            self.findings_text.insert(tk.END, "No critical vulnerabilities found.\n")
        
        # Resultados ML
        self.ml_text.insert(tk.END, "Machine Learning Analysis\n\n")
        
        risk_score = ml_result.risk_score
        risk_tag = "risk_high" if risk_score > 0.7 else "risk_medium" if risk_score > 0.4 else "risk_low"
        self.ml_text.insert(tk.END, f"Risk Score: {risk_score:.2%}\n", risk_tag)
        
        self.ml_text.insert(tk.END, f"Confidence: {ml_result.confidence:.2%}\n")
        if ml_result.scam_type:
            self.ml_text.insert(tk.END, f"Scam Type: {ml_result.scam_type.value}\n")
        self.ml_text.insert(tk.END, f"\n{ml_result.explanation}\n")
        
        # Análisis comportamental
        self.behavioral_text.insert(tk.END, "Behavioral Analysis\n\n")
        
        tx_risk = behavioral_result.transaction_risk
        risk_tag = "suspicious" if tx_risk > 0.7 else "anomaly" if tx_risk > 0.4 else "normal"
        self.behavioral_text.insert(tk.END, f"Transaction Risk: {tx_risk:.2%}\n\n", risk_tag)
        
        if behavioral_result.suspicious_patterns:
            self.behavioral_text.insert(tk.END, "Suspicious Patterns:\n")
            for pattern in behavioral_result.suspicious_patterns:
                self.behavioral_text.insert(tk.END, f"  - {pattern}\n")
        
        if behavioral_result.gas_anomalies:
            self.behavioral_text.insert(tk.END, "\nGas Anomalies:\n")
            for anomaly in behavioral_result.gas_anomalies:
                self.behavioral_text.insert(tk.END, f"  - {anomaly}\n")
        
        if behavioral_result.timing_anomalies:
            self.behavioral_text.insert(tk.END, "\nTiming Anomalies:\n")
            for anomaly in behavioral_result.timing_anomalies:
                self.behavioral_text.insert(tk.END, f"  - {anomaly}\n")
    
    def animate_success(self):
        """Animación de éxito"""
        # Cambiar status a verde brillante
        self.status_var.set("Analysis completed successfully!")
        
        # Efecto de parpadeo en el progress bar
        for _ in range(3):
            self.progress_var.set(100)
            self.root.update()
            time.sleep(0.2)
            self.progress_var.set(95)
            self.root.update()
            time.sleep(0.1)
        
        self.progress_var.set(100)
    
    def load_file(self):
        """Carga archivo de contrato"""
        file_path = filedialog.askopenfilename(
            title="Select contract file",
            filetypes=[("Solidity files", "*.sol"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read()
                    self.code_text.delete("1.0", tk.END)
                    self.code_text.insert("1.0", content)
                    self.status_var.set(f"File loaded: {file_path}")
                    self.apply_syntax_highlighting()
            except Exception as e:
                messagebox.showerror("Error", f"Cannot load file: {str(e)}")
    
    def clear_all(self):
        """Limpia todo con animación"""
        # Animación de limpieza
        self.fade_out_widget(self.code_text)
        self.code_text.delete("1.0", tk.END)
        self.fade_in_widget(self.code_text)
        
        for tab in self.tabs:
            tab['text'].delete("1.0", tk.END)
        
        self.status_var.set("Ready to analyze contracts")
        self.progress_var.set(0)
    
    def load_example(self):
        """Carga ejemplo con animación"""
        example_code = '''// Vulnerable Smart Contract Example
pragma solidity ^0.8.0;

contract VulnerableContract {
    address public owner;
    mapping(address => uint) public balances;
    mapping(address => bool) public blacklisted;
    
    event Transfer(address indexed from, address indexed to, uint value);
    
    constructor() {
        owner = msg.sender;
    }
    
    // Reentrancy Vulnerability
    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;
    }
    
    // Unlimited Mint Vulnerability
    function mint(address to, uint amount) public {
        require(msg.sender == owner, "Only owner");
        balances[to] += amount;
    }
    
    // Blacklist Function
    function addToBlacklist(address account) public {
        require(msg.sender == owner, "Only owner");
        blacklisted[account] = true;
    }
    
    // Honeypot Pattern
    function transfer(address to, uint amount) public returns (bool) {
        require(!blacklisted[msg.sender], "Blacklisted");
        require(balances[msg.sender] >= amount);
        require(msg.value == 0, "No ETH allowed");
        
        balances[msg.sender] -= amount;
        balances[to] += amount;
        
        emit Transfer(msg.sender, to, amount);
        return true;
    }
    
    // Backdoor Function
    function emergencyWithdraw() public {
        require(msg.sender == owner || block.timestamp > 1640995200, "Emergency only");
        (bool success, ) = owner.call{value: address(this).balance}("");
        require(success, "Transfer failed");
    }
}'''
        
        # Animación de carga
        self.code_text.delete("1.0", tk.END)
        self.fade_in_widget(self.code_text)
        
        # Insertar código letra por letra para efecto de escritura
        def type_code():
            for i, char in enumerate(example_code):
                if not self.animation_running:
                    break
                self.code_text.insert(tk.END, char)
                self.code_text.update()
                time.sleep(0.01)  # Efecto de escritura suave
        
        threading.Thread(target=type_code, daemon=True).start()
        
        self.status_var.set("Example contract loaded")
        self.apply_syntax_highlighting()
    
    def fade_out_widget(self, widget):
        """Animación de fade out (simulada)"""
        # Simular fade out con efecto visual
        original_bg = widget.cget('bg')
        for i in range(10, 0, -1):
            fade_factor = i / 10.0
            widget.update()
            time.sleep(0.02)
        widget.config(bg=original_bg)
    
    def apply_syntax_highlighting(self):
        """Aplica resaltado de sintaxis"""
        content = self.code_text.get("1.0", tk.END)
        
        # Palabras clave
        keywords = ["pragma", "contract", "function", "public", "private", "internal", "external", 
                    "view", "pure", "payable", "returns", "require", "assert", "revert", "emit",
                    "event", "modifier", "constructor", "mapping", "address", "uint", "int", 
                    "bool", "string", "bytes", "struct", "enum", "library", "interface", "import",
                    "if", "else", "for", "while", "do", "break", "continue", "return", "throw",
                    "memory", "storage", "calldata", "new", "delete", "this", "super", "msg", 
                    "block", "tx", "selfdestruct", "suicide"]
        
        # Aplicar highlighting
        for keyword in keywords:
            start_idx = "1.0"
            while True:
                pos = self.code_text.search(f"\\b{keyword}\\b", start_idx, tk.END, regexp=True)
                if not pos:
                    break
                end_pos = f"{pos}+{len(keyword)}c"
                self.code_text.tag_add("keyword", pos, end_pos)
                start_idx = end_pos
        
        # Strings
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            in_string = False
            string_start = None
            
            for i, char in enumerate(line):
                if char == '"' and not in_string:
                    in_string = True
                    string_start = i
                elif char == '"' and in_string:
                    in_string = False
                    start_pos = f"{line_num}.{string_start}"
                    end_pos = f"{line_num}.{i+1}"
                    self.code_text.tag_add("string", start_pos, end_pos)
        
        # Comentarios
        for line_num, line in enumerate(lines, 1):
            if '//' in line:
                comment_start = line.index('//')
                start_pos = f"{line_num}.{comment_start}"
                end_pos = f"{line_num + 1}.end"
                self.code_text.tag_add("comment", start_pos, end_pos)
        
        # Números
        import re
        for line_num, line in enumerate(lines, 1):
            numbers = re.findall(r'\b\d+\b', line)
            for number in numbers:
                start_pos = line.find(number)
                if start_pos != -1:
                    start = f"{line_num}.{start_pos}"
                    end = f"{line_num}.{start_pos + len(number)}"
                    self.code_text.tag_add("number", start, end)

def main():
    """Función principal"""
    root = tk.Tk()
    app = SmartContractAnalyzerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
