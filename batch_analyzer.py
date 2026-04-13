#!/usr/bin/env python3
"""
Batch Analysis System
Multi-contract analysis, repository scanning, CI/CD integration
"""

import os
import json
import requests
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import tempfile
import zipfile
import shutil

from smart_contract_analyzer import SecurityAnalyzer, MLAnalysisResult, BehavioralAnalysisResult
from blockchain_integration import BlockchainExplorer, EtherscanExplorer, OnChainAnalyzer
from reporting_system import ReportingSystem, ReportData

@dataclass
class BatchJob:
    """Trabajo de análisis batch"""
    job_id: str
    contract_address: Optional[str]
    source_code: Optional[str]
    file_path: Optional[str]
    repository_url: Optional[str]
    status: str  # pending, running, completed, failed
    result: Optional[Dict]
    error: Optional[str]
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]

@dataclass
class RepositoryInfo:
    """Información de repositorio"""
    url: str
    name: str
    owner: str
    default_branch: str
    clone_url: str
    last_commit: str
    commit_date: datetime

@dataclass
class BatchAnalysisResult:
    """Resultado de análisis batch"""
    total_contracts: int
    successful_analyses: int
    failed_analyses: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    analysis_duration: float
    results: List[Dict]

class GitHubScanner:
    """Scanner de repositorios GitHub"""
    
    def __init__(self, github_token: str = None):
        self.github_token = github_token
        self.session = requests.Session()
        if github_token:
            self.session.headers.update({
                'Authorization': f'token {github_token}'
            })
    
    def search_repositories(self, query: str, limit: int = 50) -> List[RepositoryInfo]:
        """Busca repositorios por query"""
        url = "https://api.github.com/search/repositories"
        params = {
            'q': query,
            'sort': 'stars',
            'order': 'desc',
            'per_page': min(limit, 100)
        }
        
        response = self.session.get(url, params=params)
        response.raise_for_status()
        
        repos = []
        for repo in response.json().get('items', []):
            repo_info = RepositoryInfo(
                url=repo['html_url'],
                name=repo['name'],
                owner=repo['owner']['login'],
                default_branch=repo['default_branch'],
                clone_url=repo['clone_url'],
                last_commit=repo['pushed_at'],
                commit_date=datetime.fromisoformat(repo['pushed_at'].replace('Z', '+00:00'))
            )
            repos.append(repo_info)
        
        return repos
    
    def get_repository_files(self, repo_info: RepositoryInfo, file_pattern: str = "*.sol") -> List[str]:
        """Obtiene lista de archivos Solidity del repositorio"""
        url = f"https://api.github.com/repos/{repo_info.owner}/{repo_info.name}/git/trees/{repo_info.default_branch}"
        params = {'recursive': '1'}
        
        response = self.session.get(url, params=params)
        response.raise_for_status()
        
        files = []
        for item in response.json().get('tree', []):
            if item['type'] == 'file' and item['path'].endswith('.sol'):
                files.append(item['path'])
        
        return files
    
    def download_file(self, repo_info: RepositoryInfo, file_path: str) -> str:
        """Descarga contenido de archivo"""
        url = f"https://api.github.com/repos/{repo_info.owner}/{repo_info.name}/contents/{file_path}"
        
        response = self.session.get(url)
        response.raise_for_status()
        
        content = response.json().get('content', '')
        if content:
            import base64
            return base64.b64decode(content).decode('utf-8')
        
        return ""
    
    def clone_repository(self, repo_info: RepositoryInfo, target_dir: str) -> str:
        """Clona repositorio localmente"""
        clone_path = os.path.join(target_dir, repo_info.name)
        
        if os.path.exists(clone_path):
            shutil.rmtree(clone_path)
        
        subprocess.run(['git', 'clone', repo_info.clone_url, clone_path], 
                       check=True, capture_output=True)
        
        return clone_path

class BatchAnalyzer:
    """Analizador batch principal"""
    
    def __init__(self, max_workers: int = 5):
        self.max_workers = max_workers
        self.security_analyzer = SecurityAnalyzer()
        self.reporting_system = ReportingSystem()
        self.jobs: Dict[str, BatchJob] = {}
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
    
    def add_contract_analysis_job(self, contract_address: str) -> str:
        """Añade trabajo de análisis de contrato por dirección"""
        job_id = f"contract_{contract_address}_{int(time.time())}"
        
        job = BatchJob(
            job_id=job_id,
            contract_address=contract_address,
            source_code=None,
            file_path=None,
            repository_url=None,
            status="pending",
            result=None,
            error=None,
            created_at=datetime.now(),
            started_at=None,
            completed_at=None
        )
        
        self.jobs[job_id] = job
        return job_id
    
    def add_source_code_job(self, source_code: str, name: str = "source") -> str:
        """Añade trabajo de análisis por código fuente"""
        job_id = f"source_{name}_{int(time.time())}"
        
        job = BatchJob(
            job_id=job_id,
            contract_address=None,
            source_code=source_code,
            file_path=None,
            repository_url=None,
            status="pending",
            result=None,
            error=None,
            created_at=datetime.now(),
            started_at=None,
            completed_at=None
        )
        
        self.jobs[job_id] = job
        return job_id
    
    def add_file_analysis_job(self, file_path: str) -> str:
        """Añade trabajo de análisis por archivo"""
        job_id = f"file_{os.path.basename(file_path)}_{int(time.time())}"
        
        job = BatchJob(
            job_id=job_id,
            contract_address=None,
            source_code=None,
            file_path=file_path,
            repository_url=None,
            status="pending",
            result=None,
            error=None,
            created_at=datetime.now(),
            started_at=None,
            completed_at=None
        )
        
        self.jobs[job_id] = job
        return job_id
    
    def add_repository_scan_job(self, repository_url: str) -> str:
        """Añade trabajo de escaneo de repositorio"""
        job_id = f"repo_{repository_url.split('/')[-1]}_{int(time.time())}"
        
        job = BatchJob(
            job_id=job_id,
            contract_address=None,
            source_code=None,
            file_path=None,
            repository_url=repository_url,
            status="pending",
            result=None,
            error=None,
            created_at=datetime.now(),
            started_at=None,
            completed_at=None
        )
        
        self.jobs[job_id] = job
        return job_id
    
    def run_batch_analysis(self, job_ids: List[str] = None) -> BatchAnalysisResult:
        """Ejecuta análisis batch"""
        if job_ids is None:
            job_ids = list(self.jobs.keys())
        
        start_time = time.time()
        futures = {}
        
        # Iniciar trabajos en paralelo
        for job_id in job_ids:
            job = self.jobs[job_id]
            if job.status == "pending":
                future = self.executor.submit(self._process_job, job_id)
                futures[future] = job_id
        
        # Esperar resultados
        results = []
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        for future in as_completed(futures):
            job_id = futures[future]
            try:
                result = future.result()
                results.append(result)
                
                # Contar severidades
                if result and 'findings' in result:
                    for finding in result['findings']:
                        severity = finding.get('severity', '').lower()
                        if severity == 'critical':
                            critical_count += 1
                        elif severity == 'high':
                            high_count += 1
                        elif severity == 'medium':
                            medium_count += 1
                        elif severity == 'low':
                            low_count += 1
                
                self.jobs[job_id].status = "completed"
                self.jobs[job_id].completed_at = datetime.now()
                
            except Exception as e:
                self.jobs[job_id].status = "failed"
                self.jobs[job_id].error = str(e)
                self.jobs[job_id].completed_at = datetime.now()
        
        duration = time.time() - start_time
        
        return BatchAnalysisResult(
            total_contracts=len(job_ids),
            successful_analyses=len([r for r in results if r]),
            failed_analyses=len(job_ids) - len(results),
            critical_findings=critical_count,
            high_findings=high_count,
            medium_findings=medium_count,
            low_findings=low_count,
            analysis_duration=duration,
            results=results
        )
    
    def _process_job(self, job_id: str) -> Optional[Dict]:
        """Procesa un trabajo individual"""
        job = self.jobs[job_id]
        job.status = "running"
        job.started_at = datetime.now()
        
        try:
            if job.contract_address:
                return self._analyze_contract_address(job.contract_address)
            elif job.source_code:
                return self._analyze_source_code(job.source_code)
            elif job.file_path:
                return self._analyze_file(job.file_path)
            elif job.repository_url:
                return self._scan_repository(job.repository_url)
            else:
                raise ValueError("Job has no valid content to analyze")
        
        except Exception as e:
            job.error = str(e)
            raise
    
    def _analyze_contract_address(self, address: str) -> Dict:
        """Analiza contrato por dirección"""
        # Implementar con blockchain integration
        findings, ml_result, behavioral_result = self.security_analyzer.analyze_code("")
        
        return {
            'address': address,
            'findings': [asdict(f) for f in findings],
            'ml_analysis': asdict(ml_result),
            'behavioral_analysis': asdict(behavioral_result)
        }
    
    def _analyze_source_code(self, source_code: str) -> Dict:
        """Analiza código fuente"""
        findings, ml_result, behavioral_result = self.security_analyzer.analyze_code(source_code)
        
        return {
            'source_code_length': len(source_code),
            'findings': [asdict(f) for f in findings],
            'ml_analysis': asdict(ml_result),
            'behavioral_analysis': asdict(behavioral_result)
        }
    
    def _analyze_file(self, file_path: str) -> Dict:
        """Analiza archivo"""
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        result = self._analyze_source_code(content)
        result['file_path'] = file_path
        result['file_size'] = len(content)
        
        return result
    
    def _scan_repository(self, repository_url: str) -> Dict:
        """Escanea repositorio completo"""
        # Extraer owner/repo de URL
        parts = repository_url.rstrip('/').split('/')
        if len(parts) < 2:
            raise ValueError("Invalid repository URL")
        
        owner, repo = parts[-2], parts[-1]
        
        # Crear directorio temporal
        with tempfile.TemporaryDirectory() as temp_dir:
            # Clonar repositorio
            clone_path = os.path.join(temp_dir, repo)
            subprocess.run(['git', 'clone', repository_url, clone_path], 
                           check=True, capture_output=True)
            
            # Encontrar archivos .sol
            sol_files = []
            for root, dirs, files in os.walk(clone_path):
                for file in files:
                    if file.endswith('.sol'):
                        sol_files.append(os.path.join(root, file))
            
            # Analizar cada archivo
            results = []
            for sol_file in sol_files:
                try:
                    result = self._analyze_file(sol_file)
                    results.append(result)
                except Exception as e:
                    print(f"Error analyzing {sol_file}: {e}")
        
        return {
            'repository_url': repository_url,
            'total_files': len(sol_files),
            'analyzed_files': len(results),
            'file_results': results
        }
    
    def generate_batch_report(self, batch_result: BatchAnalysisResult, output_dir: str = None) -> str:
        """Genera reporte batch"""
        if output_dir is None:
            output_dir = Path(__file__).parent / "batch_reports"
            output_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = output_dir / f"batch_report_{timestamp}.json"
        
        # Crear reporte batch
        report_data = {
            'summary': {
                'total_contracts': batch_result.total_contracts,
                'successful_analyses': batch_result.successful_analyses,
                'failed_analyses': batch_result.failed_analyses,
                'critical_findings': batch_result.critical_findings,
                'high_findings': batch_result.high_findings,
                'medium_findings': batch_result.medium_findings,
                'low_findings': batch_result.low_findings,
                'analysis_duration': batch_result.analysis_duration,
                'generated_at': datetime.now().isoformat()
            },
            'results': batch_result.results
        }
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        return str(report_path)

class CICDIntegration:
    """Integración con CI/CD"""
    
    def __init__(self):
        self.batch_analyzer = BatchAnalyzer()
    
    def create_github_action(self, output_dir: str = None) -> str:
        """Crea archivo GitHub Action para análisis automático"""
        if output_dir is None:
            output_dir = Path(__file__).parent / "ci_cd_templates"
            output_dir.mkdir(exist_ok=True)
        
        github_action = """name: Smart Contract Analysis

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  analyze:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install requests matplotlib seaborn pandas jinja2
    
    - name: Find Solidity files
      id: find-files
      run: |
        echo "sol_files=$(find . -name '*.sol' -type f | tr '\\n' ' ')" >> $GITHUB_OUTPUT
    
    - name: Run Smart Contract Analyzer
      run: |
        python smart_contract_analyzer.py --batch --files "${{ steps.find-files.outputs.sol_files }}"
    
    - name: Generate Report
      run: |
        python batch_analyzer.py --generate-report --output reports/
    
    - name: Upload Reports
      uses: actions/upload-artifact@v3
      with:
        name: analysis-reports
        path: reports/
    
    - name: Comment PR
      if: github.event_name == 'pull_request'
      uses: actions/github-script@v6
      with:
        script: |
          const fs = require('fs');
          const reportPath = 'reports/batch_report_latest.json';
          
          if (fs.existsSync(reportPath)) {
            const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
            const summary = report.summary;
            
            const comment = `## Smart Contract Analysis Report
            
**Summary:**
- Total Contracts: ${summary.total_contracts}
- Successful Analyses: ${summary.successful_analyses}
- Failed Analyses: ${summary.failed_analyses}

**Findings:**
- Critical: ${summary.critical_findings}
- High: ${summary.high_findings}
- Medium: ${summary.medium_findings}
- Low: ${summary.low_findings}

**Analysis Duration:** ${summary.analysis_duration.toFixed(2)}s

[View Detailed Report](${context.repository.html_url}/actions/runs/${context.runId})
            `;
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            });
          }
    
    - name: Check for Critical Issues
      run: |
        python -c "
        import json
        import sys
        
        with open('reports/batch_report_latest.json', 'r') as f:
            report = json.load(f)
        
        if report['summary']['critical_findings'] > 0:
            print('CRITICAL: Critical security issues found!')
            sys.exit(1)
        "
"""
        
        action_path = output_dir / "smart-contract-analysis.yml"
        with open(action_path, 'w') as f:
            f.write(github_action)
        
        return str(action_path)
    
    def create_jenkins_pipeline(self, output_dir: str = None) -> str:
        """Crea pipeline de Jenkins"""
        if output_dir is None:
            output_dir = Path(__file__).parent / "ci_cd_templates"
            output_dir.mkdir(exist_ok=True)
        
        jenkinsfile = """pipeline {
    agent any
    
    environment {
        PYTHON_VERSION = '3.9'
        REPORTS_DIR = 'reports'
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Setup Python') {
            steps {
                sh '''
                    python${PYTHON_VERSION} -m pip install --upgrade pip
                    pip install requests matplotlib seaborn pandas jinja2
                '''
            }
        }
        
        stage('Find Contracts') {
            steps {
                script {
                    env.SOL_FILES = sh(
                        script: 'find . -name "*.sol" -type f | tr "\\n" " "',
                        returnStdout: true
                    ).trim()
                }
            }
        }
        
        stage('Analyze') {
            steps {
                sh '''
                    python smart_contract_analyzer.py --batch --files "${env.SOL_FILES}"
                    python batch_analyzer.py --generate-report --output ${REPORTS_DIR}/
                '''
            }
        }
        
        stage('Archive Reports') {
            steps {
                archiveArtifacts artifacts: '${REPORTS_DIR}/**', fingerprint: true
            }
        }
        
        stage('Check Results') {
            steps {
                script {
                    def report = readJSON file: '${REPORTS_DIR}/batch_report_latest.json'
                    
                    if (report.summary.critical_findings > 0) {
                        error("CRITICAL: Critical security issues found!")
                    }
                    
                    // Publicar métricas
                    def metrics = [
                        "total_contracts=${report.summary.total_contracts}",
                        "successful_analyses=${report.summary.successful_analyses}",
                        "critical_findings=${report.summary.critical_findings}",
                        "high_findings=${report.summary.high_findings}"
                    ]
                    
                    metrics.each { metric ->
                        echo "METRIC: ${metric}"
                    }
                }
            }
        }
    }
    
    post {
        always {
            cleanWs()
        }
        
        success {
            echo "Smart Contract Analysis completed successfully!"
        }
        
        failure {
            echo "Smart Contract Analysis failed!"
            mail to: 'dev-team@company.com',
                 subject: "Smart Contract Analysis Failed",
                 body: "The analysis failed. Check the logs for details."
        }
    }
}
"""
        
        jenkins_path = output_dir / "Jenkinsfile"
        with open(jenkins_path, 'w') as f:
            f.write(jenkinsfile)
        
        return str(jenkins_path)
    
    def create_gitlab_ci(self, output_dir: str = None) -> str:
        """Crea .gitlab-ci.yml"""
        if output_dir is None:
            output_dir = Path(__file__).parent / "ci_cd_templates"
            output_dir.mkdir(exist_ok=True)
        
        gitlab_ci = """stages:
  - analyze
  - report
  - notify

variables:
  PYTHON_VERSION: "3.9"
  REPORTS_DIR: "reports"

analyze_contracts:
  stage: analyze
  image: python:${PYTHON_VERSION}
  before_script:
    - python -m pip install --upgrade pip
    - pip install requests matplotlib seaborn pandas jinja2
  script:
    - echo "Finding Solidity files..."
    - SOL_FILES=$(find . -name "*.sol" -type f | tr '\\n' ' ')
    - echo "Found files: $SOL_FILES"
    - python smart_contract_analyzer.py --batch --files "$SOL_FILES"
    - python batch_analyzer.py --generate-report --output $REPORTS_DIR/
  artifacts:
    paths:
      - $REPORTS_DIR/
    reports:
      junit: $REPORTS_DIR/junit-report.xml
    expire_in: 1 week
  only:
    - merge_requests
    - main
    - develop

generate_report:
  stage: report
  image: python:${PYTHON_VERSION}
  dependencies:
    - analyze_contracts
  script:
    - python batch_analyzer.py --generate-summary --output $REPORTS_DIR/
    - python batch_analyzer.py --generate-html --output $REPORTS_DIR/
  artifacts:
    paths:
      - $REPORTS_DIR/
    expire_in: 1 week
  only:
    - merge_requests
    - main
    - develop

security_check:
  stage: notify
  image: python:${PYTHON_VERSION}
  dependencies:
    - analyze_contracts
  script:
    - python -c "
import json
import sys

with open('$REPORTS_DIR/batch_report_latest.json', 'r') as f:
    report = json.load(f)

if report['summary']['critical_findings'] > 0:
    print('CRITICAL: Critical security issues found!')
    sys.exit(1)
"
  allow_failure: false
  only:
    - merge_requests
    - main

notify_slack:
  stage: notify
  image: alpine:latest
  dependencies:
    - generate_report
  script:
    - |
      if [ "$CI_PIPELINE_SOURCE" = "merge_request" ]; then
        curl -X POST -H 'Content-type: application/json' \\
          --data '{"text":"Smart Contract Analysis completed for MR $CI_MERGE_REQUEST_IID!\\nResults: $CI_JOB_URL"}' \\
          $SLACK_WEBHOOK_URL
      fi
  when: on_success
  only:
    - merge_requests
    - main
"""
        
        gitlab_path = output_dir / ".gitlab-ci.yml"
        with open(gitlab_path, 'w') as f:
            f.write(gitlab_ci)
        
        return str(gitlab_path)

# Demo
def demo_batch_analysis():
    """Demostración del sistema batch"""
    analyzer = BatchAnalyzer()
    
    # Añadir trabajos de ejemplo
    job1 = analyzer.add_source_code_job("contract code 1", "test1")
    job2 = analyzer.add_source_code_job("contract code 2", "test2")
    
    # Ejecutar análisis batch
    result = analyzer.run_batch_analysis([job1, job2])
    
    print("Batch Analysis Results:")
    print(f"Total Contracts: {result.total_contracts}")
    print(f"Successful: {result.successful_analyses}")
    print(f"Failed: {result.failed_analyses}")
    print(f"Critical Findings: {result.critical_findings}")
    print(f"High Findings: {result.high_findings}")
    print(f"Duration: {result.analysis_duration:.2f}s")
    
    # Generar reporte
    report_path = analyzer.generate_batch_report(result)
    print(f"Report generated: {report_path}")

if __name__ == "__main__":
    demo_batch_analysis()
