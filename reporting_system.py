#!/usr/bin/env python3
"""
Advanced Reporting System
PDF Reports, JSON/XML Export, Interactive HTML Reports
"""

import json
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
import os
import tempfile
import webbrowser
from pathlib import Path
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from jinja2 import Template
import base64
from io import BytesIO

@dataclass
class ReportData:
    """Estructura de datos para reportes"""
    contract_address: str
    contract_name: Optional[str]
    analysis_date: datetime
    findings: List[Dict]
    ml_analysis: Dict
    behavioral_analysis: Dict
    onchain_data: Optional[Dict]
    risk_score: float
    severity_summary: Dict[str, int]
    recommendations: List[str]
    executive_summary: str

class PDFReportGenerator:
    """Generador de reportes PDF profesionales"""
    
    def __init__(self):
        self.template_dir = Path(__file__).parent / "templates"
        self.output_dir = Path(__file__).parent / "reports"
        self.output_dir.mkdir(exist_ok=True)
    
    def generate_pdf_report(self, report_data: ReportData, output_path: str = None) -> str:
        """Genera reporte PDF profesional"""
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = self.output_dir / f"contract_analysis_{timestamp}.pdf"
        
        # Crear contenido HTML con CSS para PDF
        html_content = self._generate_html_report(report_data)
        
        # Usar weasyprint o similar para convertir a PDF
        # Por ahora, guardamos como HTML que puede convertirse a PDF
        html_path = str(output_path).replace('.pdf', '.html')
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return html_path
    
    def _generate_html_report(self, report_data: ReportData) -> str:
        """Genera contenido HTML para el reporte"""
        html_template = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Smart Contract Analysis Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        
        .container {
            background: white;
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
        }
        
        .header {
            text-align: center;
            margin-bottom: 40px;
            padding-bottom: 20px;
            border-bottom: 3px solid #667eea;
        }
        
        .header h1 {
            color: #2c3e50;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header .subtitle {
            color: #7f8c8d;
            font-size: 1.2em;
        }
        
        .section {
            margin-bottom: 30px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 10px;
            border-left: 4px solid #667eea;
        }
        
        .section h2 {
            color: #2c3e50;
            margin-top: 0;
            font-size: 1.8em;
        }
        
        .risk-score {
            text-align: center;
            padding: 30px;
            background: linear-gradient(135deg, #ff6b6b 0%, #ffd93d 100%);
            border-radius: 15px;
            margin: 20px 0;
        }
        
        .risk-score h3 {
            color: white;
            font-size: 2em;
            margin: 0;
        }
        
        .risk-score .score {
            font-size: 4em;
            font-weight: bold;
            color: white;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .severity-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .severity-card {
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            color: white;
            font-weight: bold;
        }
        
        .critical { background: linear-gradient(135deg, #e74c3c, #c0392b); }
        .high { background: linear-gradient(135deg, #f39c12, #e67e22); }
        .medium { background: linear-gradient(135deg, #3498db, #2980b9); }
        .low { background: linear-gradient(135deg, #95a5a6, #7f8c8d); }
        .info { background: linear-gradient(135deg, #2ecc71, #27ae60); }
        
        .finding {
            margin: 15px 0;
            padding: 15px;
            background: white;
            border-radius: 8px;
            border-left: 4px solid #e74c3c;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        
        .finding.critical { border-left-color: #e74c3c; }
        .finding.high { border-left-color: #f39c12; }
        .finding.medium { border-left-color: #3498db; }
        .finding.low { border-left-color: #95a5a6; }
        .finding.info { border-left-color: #2ecc71; }
        
        .finding-title {
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 5px;
        }
        
        .finding-details {
            color: #7f8c8d;
            font-size: 0.9em;
        }
        
        .recommendations {
            background: #e8f5e8;
            border-left: 4px solid #2ecc71;
        }
        
        .recommendations ul {
            margin: 0;
            padding-left: 20px;
        }
        
        .recommendations li {
            margin: 10px 0;
            color: #27ae60;
        }
        
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ecf0f1;
            color: #7f8c8d;
        }
        
        .chart-container {
            margin: 20px 0;
            text-align: center;
        }
        
        .executive-summary {
            background: linear-gradient(135deg, #3498db, #2980b9);
            color: white;
            padding: 30px;
            border-radius: 15px;
            margin: 20px 0;
        }
        
        .executive-summary h2 {
            color: white;
            margin-top: 0;
        }
        
        @media print {
            body { background: white; }
            .container { box-shadow: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Smart Contract Analysis Report</h1>
            <div class="subtitle">
                Contract: {{ contract_address }}<br>
                Date: {{ analysis_date.strftime('%Y-%m-%d %H:%M:%S') }}
            </div>
        </div>
        
        <div class="executive-summary">
            <h2>Executive Summary</h2>
            <p>{{ executive_summary }}</p>
        </div>
        
        <div class="risk-score">
            <h3>Overall Risk Score</h3>
            <div class="score">{{ "%.1f"|format(risk_score * 100) }}%</div>
        </div>
        
        <div class="section">
            <h2>Severity Distribution</h2>
            <div class="severity-grid">
                <div class="severity-card critical">
                    <div>Critical</div>
                    <div style="font-size: 2em;">{{ severity_summary.critical or 0 }}</div>
                </div>
                <div class="severity-card high">
                    <div>High</div>
                    <div style="font-size: 2em;">{{ severity_summary.high or 0 }}</div>
                </div>
                <div class="severity-card medium">
                    <div>Medium</div>
                    <div style="font-size: 2em;">{{ severity_summary.medium or 0 }}</div>
                </div>
                <div class="severity-card low">
                    <div>Low</div>
                    <div style="font-size: 2em;">{{ severity_summary.low or 0 }}</div>
                </div>
                <div class="severity-card info">
                    <div>Info</div>
                    <div style="font-size: 2em;">{{ severity_summary.info or 0 }}</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>Security Findings</h2>
            {% for finding in findings %}
            <div class="finding {{ finding.severity.lower() }}">
                <div class="finding-title">{{ finding.title }}</div>
                <div class="finding-details">
                    <strong>Severity:</strong> {{ finding.severity }}<br>
                    {% if finding.line_number %}
                    <strong>Line:</strong> {{ finding.line_number }}<br>
                    {% endif %}
                    <strong>Description:</strong> {{ finding.description }}<br>
                    {% if finding.recommendation %}
                    <strong>Recommendation:</strong> {{ finding.recommendation }}
                    {% endif %}
                </div>
            </div>
            {% endfor %}
        </div>
        
        <div class="section">
            <h2>Machine Learning Analysis</h2>
            <p><strong>Risk Score:</strong> {{ "%.2f"|format(ml_analysis.risk_score) }}</p>
            <p><strong>Confidence:</strong> {{ "%.2f"|format(ml_analysis.confidence) }}</p>
            {% if ml_analysis.scam_type %}
            <p><strong>Predicted Scam Type:</strong> {{ ml_analysis.scam_type }}</p>
            {% endif %}
            <p><strong>Key Features:</strong></p>
            <ul>
                {% for feature, value in ml_analysis.features.items() %}
                <li>{{ feature }}: {{ "%.2f"|format(value) }}</li>
                {% endfor %}
            </ul>
        </div>
        
        <div class="section">
            <h2>Behavioral Analysis</h2>
            <p><strong>Transaction Risk:</strong> {{ "%.2f"|format(behavioral_analysis.transaction_risk) }}</p>
            {% if behavioral_analysis.suspicious_patterns %}
            <p><strong>Suspicious Patterns:</strong></p>
            <ul>
                {% for pattern in behavioral_analysis.suspicious_patterns %}
                <li>{{ pattern }}</li>
                {% endfor %}
            </ul>
            {% endif %}
        </div>
        
        {% if onchain_data %}
        <div class="section">
            <h2>On-Chain Analysis</h2>
            <p><strong>Balance:</strong> {{ onchain_data.balance }} ETH</p>
            <p><strong>Transaction Count:</strong> {{ onchain_data.transaction_count }}</p>
            <p><strong>Last Activity:</strong> {{ onchain_data.last_activity.strftime('%Y-%m-%d %H:%M:%S') }}</p>
        </div>
        {% endif %}
        
        <div class="section recommendations">
            <h2>Recommendations</h2>
            <ul>
                {% for rec in recommendations %}
                <li>{{ rec }}</li>
                {% endfor %}
            </ul>
        </div>
        
        <div class="footer">
            <p>Generated by Smart Contract Analyzer Enhanced</p>
            <p>Report ID: {{ contract_address[:8] }}-{{ analysis_date.strftime('%Y%m%d%H%M%S') }}</p>
        </div>
    </div>
</body>
</html>
        """
        
        template = Template(html_template)
        return template.render(
            contract_address=report_data.contract_address,
            contract_name=report_data.contract_name or "Unknown",
            analysis_date=report_data.analysis_date,
            executive_summary=report_data.executive_summary,
            risk_score=report_data.risk_score,
            severity_summary=report_data.severity_summary,
            findings=report_data.findings,
            ml_analysis=report_data.ml_analysis,
            behavioral_analysis=report_data.behavioral_analysis,
            onchain_data=report_data.onchain_data,
            recommendations=report_data.recommendations
        )

class JSONXMLExporter:
    """Exportador de datos a JSON/XML"""
    
    def export_to_json(self, report_data: ReportData, output_path: str) -> str:
        """Exporta reporte a JSON"""
        # Convertir dataclass a dict serializable
        data_dict = asdict(report_data)
        
        # Convertir datetime a string
        data_dict['analysis_date'] = report_data.analysis_date.isoformat()
        
        if data_dict['onchain_data'] and data_dict['onchain_data'].get('last_activity'):
            data_dict['onchain_data']['last_activity'] = report_data.onchain_data['last_activity'].isoformat()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data_dict, f, indent=2, ensure_ascii=False)
        
        return output_path
    
    def export_to_xml(self, report_data: ReportData, output_path: str) -> str:
        """Exporta reporte a XML"""
        root = ET.Element("SmartContractAnalysis")
        
        # Información básica
        info = ET.SubElement(root, "ContractInfo")
        ET.SubElement(info, "Address").text = report_data.contract_address
        ET.SubElement(info, "Name").text = report_data.contract_name or ""
        ET.SubElement(info, "AnalysisDate").text = report_data.analysis_date.isoformat()
        ET.SubElement(info, "RiskScore").text = str(report_data.risk_score)
        
        # Executive summary
        ET.SubElement(root, "ExecutiveSummary").text = report_data.executive_summary
        
        # Severity summary
        severity = ET.SubElement(root, "SeveritySummary")
        for sev, count in report_data.severity_summary.items():
            ET.SubElement(severity, sev).text = str(count)
        
        # Findings
        findings_elem = ET.SubElement(root, "Findings")
        for finding in report_data.findings:
            finding_elem = ET.SubElement(findings_elem, "Finding")
            ET.SubElement(finding_elem, "Title").text = finding.get('title', '')
            ET.SubElement(finding_elem, "Severity").text = finding.get('severity', '')
            ET.SubElement(finding_elem, "Description").text = finding.get('description', '')
            ET.SubElement(finding_elem, "LineNumber").text = str(finding.get('line_number', ''))
            ET.SubElement(finding_elem, "Recommendation").text = finding.get('recommendation', '')
        
        # ML Analysis
        ml_elem = ET.SubElement(root, "MLAnalysis")
        ET.SubElement(ml_elem, "RiskScore").text = str(report_data.ml_analysis.get('risk_score', 0))
        ET.SubElement(ml_elem, "Confidence").text = str(report_data.ml_analysis.get('confidence', 0))
        ET.SubElement(ml_elem, "ScamType").text = str(report_data.ml_analysis.get('scam_type', ''))
        
        # Behavioral Analysis
        behavioral_elem = ET.SubElement(root, "BehavioralAnalysis")
        ET.SubElement(behavioral_elem, "TransactionRisk").text = str(report_data.behavioral_analysis.get('transaction_risk', 0))
        
        # Recommendations
        recs_elem = ET.SubElement(root, "Recommendations")
        for rec in report_data.recommendations:
            ET.SubElement(recs_elem, "Recommendation").text = rec
        
        # Guardar XML
        tree = ET.ElementTree(root)
        tree.write(output_path, encoding='utf-8', xml_declaration=True)
        
        return output_path

class InteractiveHTMLGenerator:
    """Generador de reportes HTML interactivos"""
    
    def __init__(self):
        self.output_dir = Path(__file__).parent / "reports"
        self.output_dir.mkdir(exist_ok=True)
    
    def generate_interactive_report(self, report_data: ReportData, output_path: str = None) -> str:
        """Genera reporte HTML interactivo con charts"""
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = self.output_dir / f"interactive_report_{timestamp}.html"
        
        # Generar charts
        charts = self._generate_charts(report_data)
        
        # Crear HTML interactivo
        html_content = self._generate_interactive_html(report_data, charts)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(output_path)
    
    def _generate_charts(self, report_data: ReportData) -> Dict[str, str]:
        """Genera charts en base64 para embed en HTML"""
        charts = {}
        
        # Chart de severidad
        plt.figure(figsize=(10, 6))
        severities = list(report_data.severity_summary.keys())
        counts = list(report_data.severity_summary.values())
        colors = ['#e74c3c', '#f39c12', '#3498db', '#95a5a6', '#2ecc71']
        
        plt.bar(severities, counts, color=colors[:len(severities)])
        plt.title('Severity Distribution')
        plt.ylabel('Count')
        plt.xticks(rotation=45)
        
        # Guardar chart en base64
        buffer = BytesIO()
        plt.savefig(buffer, format='png', bbox_inches='tight', dpi=150)
        buffer.seek(0)
        charts['severity'] = base64.b64encode(buffer.read()).decode()
        plt.close()
        
        # Chart de ML features
        if report_data.ml_analysis.get('features'):
            plt.figure(figsize=(12, 8))
            features = list(report_data.ml_analysis['features'].keys())
            values = list(report_data.ml_analysis['features'].values())
            
            plt.barh(features, values, color='#3498db')
            plt.title('ML Feature Analysis')
            plt.xlabel('Feature Value')
            
            buffer = BytesIO()
            plt.savefig(buffer, format='png', bbox_inches='tight', dpi=150)
            buffer.seek(0)
            charts['features'] = base64.b64encode(buffer.read()).decode()
            plt.close()
        
        # Chart de risk score
        plt.figure(figsize=(8, 8))
        risk_score = report_data.risk_score * 100
        colors = ['#2ecc71' if risk_score < 30 else '#f39c12' if risk_score < 70 else '#e74c3c']
        
        plt.pie([risk_score, 100-risk_score], 
               labels=['Risk', 'Safe'], 
               colors=colors,
               autopct='%1.1f%%',
               startangle=90)
        plt.title(f'Risk Score: {risk_score:.1f}%')
        
        buffer = BytesIO()
        plt.savefig(buffer, format='png', bbox_inches='tight', dpi=150)
        buffer.seek(0)
        charts['risk'] = base64.b64encode(buffer.read()).decode()
        plt.close()
        
        return charts
    
    def _generate_interactive_html(self, report_data: ReportData, charts: Dict[str, str]) -> str:
        """Genera HTML interactivo con JavaScript"""
        html_template = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Interactive Smart Contract Analysis</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            margin-bottom: 40px;
            padding-bottom: 20px;
            border-bottom: 3px solid #3498db;
        }
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 15px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
        .card h3 {
            margin: 0 0 10px 0;
            font-size: 1.2em;
        }
        .card .value {
            font-size: 2.5em;
            font-weight: bold;
        }
        .chart-container {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            margin: 20px 0;
        }
        .chart-container h3 {
            margin-top: 0;
            color: #2c3e50;
        }
        .findings-table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        .findings-table th, .findings-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        .findings-table th {
            background: #3498db;
            color: white;
        }
        .severity-critical { color: #e74c3c; font-weight: bold; }
        .severity-high { color: #f39c12; font-weight: bold; }
        .severity-medium { color: #3498db; font-weight: bold; }
        .severity-low { color: #95a5a6; }
        .severity-info { color: #2ecc71; }
        .tabs {
            margin: 20px 0;
        }
        .tab-buttons {
            display: flex;
            border-bottom: 2px solid #3498db;
        }
        .tab-button {
            padding: 12px 24px;
            background: none;
            border: none;
            cursor: pointer;
            font-size: 16px;
            border-bottom: 3px solid transparent;
            transition: all 0.3s;
        }
        .tab-button.active {
            border-bottom-color: #3498db;
            color: #3498db;
            font-weight: bold;
        }
        .tab-content {
            display: none;
            padding: 20px 0;
        }
        .tab-content.active {
            display: block;
        }
        .filter-controls {
            margin: 20px 0;
            padding: 15px;
            background: #ecf0f1;
            border-radius: 10px;
        }
        .filter-controls select, .filter-controls input {
            margin: 5px;
            padding: 8px;
            border: 1px solid #bdc3c7;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Interactive Smart Contract Analysis</h1>
            <p><strong>Contract:</strong> {{ contract_address }} | <strong>Date:</strong> {{ analysis_date.strftime('%Y-%m-%d %H:%M:%S') }}</p>
        </div>
        
        <div class="dashboard">
            <div class="card">
                <h3>Risk Score</h3>
                <div class="value">{{ "%.1f"|format(risk_score * 100) }}%</div>
            </div>
            <div class="card">
                <h3>Total Findings</h3>
                <div class="value">{{ findings|length }}</div>
            </div>
            <div class="card">
                <h3>Critical Issues</h3>
                <div class="value">{{ severity_summary.critical or 0 }}</div>
            </div>
            <div class="card">
                <h3>ML Confidence</h3>
                <div class="value">{{ "%.1f"|format(ml_analysis.confidence * 100) }}%</div>
            </div>
        </div>
        
        <div class="tabs">
            <div class="tab-buttons">
                <button class="tab-button active" onclick="showTab('overview')">Overview</button>
                <button class="tab-button" onclick="showTab('findings')">Findings</button>
                <button class="tab-button" onclick="showTab('ml')">ML Analysis</button>
                <button class="tab-button" onclick="showTab('behavioral')">Behavioral</button>
                {% if onchain_data %}
                <button class="tab-button" onclick="showTab('onchain')">On-Chain</button>
                {% endif %}
            </div>
            
            <div id="overview" class="tab-content active">
                <div class="chart-container">
                    <h3>Risk Score Distribution</h3>
                    <canvas id="riskChart"></canvas>
                </div>
                
                <div class="chart-container">
                    <h3>Severity Distribution</h3>
                    <canvas id="severityChart"></canvas>
                </div>
                
                {% if charts.features %}
                <div class="chart-container">
                    <h3>ML Feature Analysis</h3>
                    <img src="data:image/png;base64,{{ charts.features }}" style="max-width: 100%; height: auto;">
                </div>
                {% endif %}
            </div>
            
            <div id="findings" class="tab-content">
                <div class="filter-controls">
                    <label>Filter by Severity:</label>
                    <select id="severityFilter" onchange="filterFindings()">
                        <option value="">All</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                        <option value="info">Info</option>
                    </select>
                    <label>Search:</label>
                    <input type="text" id="searchFilter" onkeyup="filterFindings()" placeholder="Search findings...">
                </div>
                
                <table class="findings-table" id="findingsTable">
                    <thead>
                        <tr>
                            <th>Title</th>
                            <th>Severity</th>
                            <th>Line</th>
                            <th>Description</th>
                            <th>Recommendation</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for finding in findings %}
                        <tr class="finding-row" data-severity="{{ finding.severity.lower() }}">
                            <td>{{ finding.title }}</td>
                            <td class="severity-{{ finding.severity.lower() }}">{{ finding.severity }}</td>
                            <td>{{ finding.line_number or '' }}</td>
                            <td>{{ finding.description }}</td>
                            <td>{{ finding.recommendation or '' }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            
            <div id="ml" class="tab-content">
                <div class="chart-container">
                    <h3>ML Risk Analysis</h3>
                    <p><strong>Risk Score:</strong> {{ "%.2f"|format(ml_analysis.risk_score) }}</p>
                    <p><strong>Confidence:</strong> {{ "%.2f"|format(ml_analysis.confidence) }}</p>
                    {% if ml_analysis.scam_type %}
                    <p><strong>Predicted Scam Type:</strong> {{ ml_analysis.scam_type }}</p>
                    {% endif %}
                </div>
                
                <div class="chart-container">
                    <h3>Feature Breakdown</h3>
                    <canvas id="featuresChart"></canvas>
                </div>
            </div>
            
            <div id="behavioral" class="tab-content">
                <div class="chart-container">
                    <h3>Behavioral Analysis</h3>
                    <p><strong>Transaction Risk:</strong> {{ "%.2f"|format(behavioral_analysis.transaction_risk) }}</p>
                    {% if behavioral_analysis.suspicious_patterns %}
                    <h4>Suspicious Patterns:</h4>
                    <ul>
                        {% for pattern in behavioral_analysis.suspicious_patterns %}
                        <li>{{ pattern }}</li>
                        {% endfor %}
                    </ul>
                    {% endif %}
                    {% if behavioral_analysis.gas_anomalies %}
                    <h4>Gas Anomalies:</h4>
                    <ul>
                        {% for anomaly in behavioral_analysis.gas_anomalies %}
                        <li>{{ anomaly }}</li>
                        {% endfor %}
                    </ul>
                    {% endif %}
                </div>
            </div>
            
            {% if onchain_data %}
            <div id="onchain" class="tab-content">
                <div class="chart-container">
                    <h3>On-Chain Analysis</h3>
                    <p><strong>Balance:</strong> {{ onchain_data.balance }} ETH</p>
                    <p><strong>Transaction Count:</strong> {{ onchain_data.transaction_count }}</p>
                    <p><strong>Last Activity:</strong> {{ onchain_data.last_activity.strftime('%Y-%m-%d %H:%M:%S') }}</p>
                </div>
            </div>
            {% endif %}
        </div>
        
        <div class="chart-container">
            <h3>Recommendations</h3>
            <ul>
                {% for rec in recommendations %}
                <li>{{ rec }}</li>
                {% endfor %}
            </ul>
        </div>
    </div>
    
    <script>
        // Tab functionality
        function showTab(tabName) {
            // Hide all tabs
            const tabs = document.querySelectorAll('.tab-content');
            tabs.forEach(tab => tab.classList.remove('active'));
            
            // Remove active class from all buttons
            const buttons = document.querySelectorAll('.tab-button');
            buttons.forEach(button => button.classList.remove('active'));
            
            // Show selected tab
            document.getElementById(tabName).classList.add('active');
            event.target.classList.add('active');
        }
        
        // Filter functionality
        function filterFindings() {
            const severityFilter = document.getElementById('severityFilter').value;
            const searchFilter = document.getElementById('searchFilter').value.toLowerCase();
            const rows = document.querySelectorAll('.finding-row');
            
            rows.forEach(row => {
                const severity = row.dataset.severity;
                const text = row.textContent.toLowerCase();
                
                const matchesSeverity = !severityFilter || severity === severityFilter;
                const matchesSearch = !searchFilter || text.includes(searchFilter);
                
                row.style.display = matchesSeverity && matchesSearch ? '' : 'none';
            });
        }
        
        // Charts
        const ctx1 = document.getElementById('riskChart').getContext('2d');
        new Chart(ctx1, {
            type: 'pie',
            data: {
                labels: ['Risk', 'Safe'],
                datasets: [{
                    data: [{{ risk_score * 100 }}, {{ (1 - risk_score) * 100 }}],
                    backgroundColor: ['#e74c3c', '#2ecc71']
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
        
        const ctx2 = document.getElementById('severityChart').getContext('2d');
        new Chart(ctx2, {
            type: 'bar',
            data: {
                labels: [{% for sev in severity_summary.keys() %}'{{ sev }}',{% endfor %}],
                datasets: [{
                    label: 'Count',
                    data: [{% for count in severity_summary.values() %}{{ count }},{% endfor %}],
                    backgroundColor: ['#e74c3c', '#f39c12', '#3498db', '#95a5a6', '#2ecc71']
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        });
        
        {% if ml_analysis.features %}
        const ctx3 = document.getElementById('featuresChart').getContext('2d');
        new Chart(ctx3, {
            type: 'bar',
            data: {
                labels: [{% for feature in ml_analysis.features.keys() %}'{{ feature }}',{% endfor %}],
                datasets: [{
                    label: 'Feature Value',
                    data: [{% for value in ml_analysis.features.values() %}{{ value }},{% endfor %}],
                    backgroundColor: '#3498db'
                }]
            },
            options: {
                responsive: true,
                indexAxis: 'y',
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        });
        {% endif %}
    </script>
</body>
</html>
        """
        
        template = Template(html_template)
        return template.render(
            contract_address=report_data.contract_address,
            contract_name=report_data.contract_name or "Unknown",
            analysis_date=report_data.analysis_date,
            risk_score=report_data.risk_score,
            findings=report_data.findings,
            severity_summary=report_data.severity_summary,
            ml_analysis=report_data.ml_analysis,
            behavioral_analysis=report_data.behavioral_analysis,
            onchain_data=report_data.onchain_data,
            recommendations=report_data.recommendations,
            charts=charts
        )

class ReportingSystem:
    """Sistema principal de reporting"""
    
    def __init__(self):
        self.pdf_generator = PDFReportGenerator()
        self.json_xml_exporter = JSONXMLExporter()
        self.html_generator = InteractiveHTMLGenerator()
    
    def generate_all_reports(self, report_data: ReportData, output_dir: str = None) -> Dict[str, str]:
        """Genera todos los formatos de reporte"""
        if output_dir is None:
            output_dir = Path(__file__).parent / "reports"
            output_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"analysis_{timestamp}"
        
        reports = {}
        
        # PDF Report (HTML por ahora)
        pdf_path = output_dir / f"{base_name}.html"
        reports['html'] = self.pdf_generator.generate_pdf_report(report_data, str(pdf_path))
        
        # JSON Export
        json_path = output_dir / f"{base_name}.json"
        reports['json'] = self.json_xml_exporter.export_to_json(report_data, str(json_path))
        
        # XML Export
        xml_path = output_dir / f"{base_name}.xml"
        reports['xml'] = self.json_xml_exporter.export_to_xml(report_data, str(xml_path))
        
        # Interactive HTML
        html_path = output_dir / f"{base_name}_interactive.html"
        reports['interactive'] = self.html_generator.generate_interactive_report(report_data, str(html_path))
        
        return reports
    
    def open_report(self, report_path: str):
        """Abre reporte en navegador"""
        webbrowser.open(f'file://{os.path.abspath(report_path)}')

# Demo
def demo_reporting():
    """Demostración del sistema de reporting"""
    from datetime import datetime
    from smart_contract_analyzer import Finding, Severity, MLAnalysisResult, BehavioralAnalysisResult
    
    # Datos de ejemplo
    report_data = ReportData(
        contract_address="0x742d35Cc6634C0532925a3b8D4C9db96C4b4Db45",
        contract_name="Uniswap V2 Router",
        analysis_date=datetime.now(),
        findings=[
            {
                'title': 'Reentrancy Vulnerability',
                'severity': 'Critical',
                'line_number': 45,
                'description': 'Potential reentrancy attack detected',
                'recommendation': 'Use checks-effects-interactions pattern'
            }
        ],
        ml_analysis={
            'risk_score': 0.75,
            'confidence': 0.85,
            'scam_type': 'Reentrancy',
            'features': {'external_calls': 0.8, 'code_complexity': 0.6}
        },
        behavioral_analysis={
            'transaction_risk': 0.7,
            'suspicious_patterns': ['High gas usage', 'Rapid transactions']
        },
        onchain_data={
            'balance': 1.5,
            'transaction_count': 1000,
            'last_activity': datetime.now()
        },
        risk_score=0.75,
        severity_summary={'critical': 1, 'high': 2, 'medium': 3, 'low': 1, 'info': 2},
        recommendations=[
            'Implement reentrancy guards',
            'Add input validation',
            'Use proper access control'
        ],
        executive_summary="The contract shows critical security vulnerabilities that require immediate attention."
    )
    
    reporting_system = ReportingSystem()
    reports = reporting_system.generate_all_reports(report_data)
    
    print("Reports generated:")
    for format_type, path in reports.items():
        print(f"  {format_type}: {path}")
    
    # Abrir reporte interactivo
    reporting_system.open_report(reports['interactive'])

if __name__ == "__main__":
    demo_reporting()
