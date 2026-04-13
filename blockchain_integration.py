#!/usr/bin/env python3
"""
Blockchain Integration Module
Integración con Etherscan, BscScan y análisis on-chain
"""

import requests
import json
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

@dataclass
class ContractInfo:
    """Información de un contrato desde blockchain"""
    address: str
    name: Optional[str]
    source_code: str
    abi: List[Dict]
    bytecode: str
    creation_tx: str
    creator: str
    balance: float
    transaction_count: int
    last_activity: datetime

@dataclass
class TransactionInfo:
    """Información de una transacción"""
    hash: str
    from_address: str
    to_address: str
    value: float
    gas_used: int
    gas_price: float
    block_number: int
    timestamp: datetime
    status: str
    input_data: str

@dataclass
class TokenHolding:
    """Información de holdings de tokens"""
    contract_address: str
    symbol: str
    name: str
    balance: float
    value_usd: float

@dataclass
class SecurityRisk:
    """Información de riesgo de seguridad"""
    address: str
    risk_score: float
    is_blacklisted: bool
    labels: List[str]
    first_seen: datetime
    last_activity: datetime

class BlockchainExplorer:
    """Clase base para exploradores de blockchain"""
    
    def __init__(self, api_key: str, network: str = "mainnet"):
        self.api_key = api_key
        self.network = network
        self.base_url = ""
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SmartContractAnalyzer/1.0'
        })
        self.rate_limit_delay = 0.2  # 200ms entre requests
    
    def _make_request(self, endpoint: str, params: Dict = None) -> Dict:
        """Realiza request a la API con rate limiting"""
        url = f"{self.base_url}{endpoint}"
        if params is None:
            params = {}
        params['apikey'] = self.api_key
        
        try:
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()
            time.sleep(self.rate_limit_delay)
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error en request a {url}: {e}")
            return {}
    
    def get_contract_source(self, address: str) -> Optional[ContractInfo]:
        """Obtiene código fuente de contrato"""
        raise NotImplementedError
    
    def get_transactions(self, address: str, limit: int = 100) -> List[TransactionInfo]:
        """Obtiene transacciones de una dirección"""
        raise NotImplementedError
    
    def get_token_holdings(self, address: str) -> List[TokenHolding]:
        """Obtiene holdings de tokens ERC-20"""
        raise NotImplementedError

class EtherscanExplorer(BlockchainExplorer):
    """Integración con Etherscan API"""
    
    def __init__(self, api_key: str, network: str = "mainnet"):
        super().__init__(api_key, network)
        if network == "mainnet":
            self.base_url = "https://api.etherscan.io/api"
        elif network == "goerli":
            self.base_url = "https://api-goerli.etherscan.io/api"
        else:
            raise ValueError(f"Red no soportada: {network}")
    
    def get_contract_source(self, address: str) -> Optional[ContractInfo]:
        """Obtiene código fuente desde Etherscan"""
        # Obtener información básica del contrato
        params = {
            'module': 'contract',
            'action': 'getsourcecode',
            'address': address
        }
        
        response = self._make_request('', params)
        
        if not response or response.get('status') != '1':
            return None
        
        result = response.get('result', [{}])[0]
        
        if not result.get('SourceCode'):
            return None
        
        # Obtener información adicional
        balance_response = self._make_request('', {
            'module': 'account',
            'action': 'balance',
            'address': address,
            'tag': 'latest'
        })
        
        tx_count_response = self._make_request('', {
            'module': 'proxy',
            'action': 'eth_getTransactionCount',
            'address': address,
            'tag': 'latest'
        })
        
        balance = float(balance_response.get('result', '0')) / 10**18 if balance_response.get('status') == '1' else 0
        tx_count = int(tx_count_response.get('result', '0x0'), 16) if tx_count_response else 0
        
        return ContractInfo(
            address=address,
            name=result.get('ContractName'),
            source_code=result.get('SourceCode'),
            abi=json.loads(result.get('ABI', '[]')),
            bytecode=result.get('Bytecode', ''),
            creation_tx=result.get('TxHash', ''),
            creator=result.get('CompilerVersion', ''),
            balance=balance,
            transaction_count=tx_count,
            last_activity=datetime.now()
        )
    
    def get_transactions(self, address: str, limit: int = 100) -> List[TransactionInfo]:
        """Obtiene transacciones desde Etherscan"""
        transactions = []
        
        # Obtener transacciones normales
        params = {
            'module': 'account',
            'action': 'txlist',
            'address': address,
            'startblock': 0,
            'endblock': 99999999,
            'page': 1,
            'offset': limit,
            'sort': 'desc'
        }
        
        response = self._make_request('', params)
        
        if response.get('status') == '1':
            for tx_data in response.get('result', []):
                tx = TransactionInfo(
                    hash=tx_data['hash'],
                    from_address=tx_data['from'],
                    to_address=tx_data['to'],
                    value=float(tx_data['value']) / 10**18,
                    gas_used=int(tx_data['gasUsed']),
                    gas_price=float(tx_data['gasPrice']) / 10**9,
                    block_number=int(tx_data['blockNumber']),
                    timestamp=datetime.fromtimestamp(int(tx_data['timeStamp'])),
                    status='success' if int(tx_data['isError']) == 0 else 'failed',
                    input_data=tx_data['input']
                )
                transactions.append(tx)
        
        return transactions
    
    def get_token_holdings(self, address: str) -> List[TokenHolding]:
        """Obtiene holdings de tokens ERC-20"""
        holdings = []
        
        params = {
            'module': 'account',
            'action': 'tokentx',
            'address': address,
            'page': 1,
            'offset': 100,
            'sort': 'desc'
        }
        
        response = self._make_request('', params)
        
        if response.get('status') == '1':
            # Agrupar por token contract
            token_balances = {}
            
            for tx in response.get('result', []):
                token_address = tx['contractAddress']
                if token_address not in token_balances:
                    token_balances[token_address] = {
                        'symbol': tx['tokenSymbol'],
                        'name': tx['tokenName'],
                        'decimals': int(tx['tokenDecimal']),
                        'balance': 0
                    }
                
                # Calcular balance basado en transacciones
                if tx['to'].lower() == address.lower():
                    token_balances[token_address]['balance'] += float(tx['value']) / (10 ** token_balances[token_address]['decimals'])
                elif tx['from'].lower() == address.lower():
                    token_balances[token_address]['balance'] -= float(tx['value']) / (10 ** token_balances[token_address]['decimals'])
            
            # Crear objetos TokenHolding
            for token_address, token_info in token_balances.items():
                if token_info['balance'] > 0:
                    holding = TokenHolding(
                        contract_address=token_address,
                        symbol=token_info['symbol'],
                        name=token_info['name'],
                        balance=token_info['balance'],
                        value_usd=0  # Requiere API de precios
                    )
                    holdings.append(holding)
        
        return holdings

class BscScanExplorer(BlockchainExplorer):
    """Integración con BscScan API"""
    
    def __init__(self, api_key: str, network: str = "mainnet"):
        super().__init__(api_key, network)
        if network == "mainnet":
            self.base_url = "https://api.bscscan.com/api"
        elif network == "testnet":
            self.base_url = "https://api-testnet.bscscan.com/api"
        else:
            raise ValueError(f"Red no soportada: {network}")
    
    def get_contract_source(self, address: str) -> Optional[ContractInfo]:
        """Obtiene código fuente desde BscScan"""
        params = {
            'module': 'contract',
            'action': 'getsourcecode',
            'address': address
        }
        
        response = self._make_request('', params)
        
        if not response or response.get('status') != '1':
            return None
        
        result = response.get('result', [{}])[0]
        
        if not result.get('SourceCode'):
            return None
        
        return ContractInfo(
            address=address,
            name=result.get('ContractName'),
            source_code=result.get('SourceCode'),
            abi=json.loads(result.get('ABI', '[]')),
            bytecode=result.get('Bytecode', ''),
            creation_tx=result.get('TxHash', ''),
            creator=result.get('CompilerVersion', ''),
            balance=0,  # Implementar si es necesario
            transaction_count=0,
            last_activity=datetime.now()
        )
    
    def get_transactions(self, address: str, limit: int = 100) -> List[TransactionInfo]:
        """Obtiene transacciones desde BscScan"""
        # Similar a Etherscan pero con URLs de BSC
        return []
    
    def get_token_holdings(self, address: str) -> List[TokenHolding]:
        """Obtiene holdings de tokens desde BscScan"""
        # Similar a Etherscan pero con tokens de BSC
        return []

class SecurityOracle:
    """Oráculos de seguridad - Chainalysis, TRM, etc."""
    
    def __init__(self, chainalysis_api_key: str = None, trm_api_key: str = None):
        self.chainalysis_key = chainalysis_api_key
        self.trm_key = trm_api_key
        self.session = requests.Session()
    
    def check_address_risk(self, address: str) -> SecurityRisk:
        """Verifica riesgo de dirección con múltiples oráculos"""
        risk_score = 0.0
        labels = []
        is_blacklisted = False
        
        # Simulación de respuestas de oráculos
        # En producción, aquí irían las llamadas reales a las APIs
        
        # Chainalysis simulation
        if self.chainalysis_key:
            # response = self._call_chainalysis(address)
            # Procesar respuesta
            pass
        
        # TRM simulation
        if self.trm_key:
            # response = self._call_trm(address)
            # Procesar respuesta
            pass
        
        # Heurísticas básicas para demostración
        if address.startswith('0xdead') or address.startswith('0xbad'):
            risk_score = 0.9
            labels = ['suspicious', 'high_risk']
            is_blacklisted = True
        
        return SecurityRisk(
            address=address,
            risk_score=risk_score,
            is_blacklisted=is_blacklisted,
            labels=labels,
            first_seen=datetime.now() - timedelta(days=30),
            last_activity=datetime.now()
        )

class OnChainAnalyzer:
    """Analizador de datos on-chain"""
    
    def __init__(self, explorer: BlockchainExplorer, security_oracle: SecurityOracle):
        self.explorer = explorer
        self.security_oracle = security_oracle
        self.executor = ThreadPoolExecutor(max_workers=5)
    
    def analyze_contract(self, address: str) -> Tuple[Optional[ContractInfo], List[TransactionInfo], List[TokenHolding], SecurityRisk]:
        """Análisis completo de un contrato"""
        futures = {}
        
        # Ejecutar análisis en paralelo
        futures['contract'] = self.executor.submit(self.explorer.get_contract_source, address)
        futures['transactions'] = self.executor.submit(self.explorer.get_transactions, address)
        futures['holdings'] = self.executor.submit(self.explorer.get_token_holdings, address)
        futures['security'] = self.executor.submit(self.security_oracle.check_address_risk, address)
        
        # Recopilar resultados
        contract_info = futures['contract'].result()
        transactions = futures['transactions'].result()
        holdings = futures['holdings'].result()
        security_risk = futures['security'].result()
        
        return contract_info, transactions, holdings, security_risk
    
    def analyze_transaction_patterns(self, transactions: List[TransactionInfo]) -> Dict:
        """Analiza patrones en transacciones"""
        if not transactions:
            return {}
        
        # Análisis temporal
        time_gaps = []
        for i in range(1, len(transactions)):
            gap = (transactions[i-1].timestamp - transactions[i].timestamp).total_seconds()
            time_gaps.append(gap)
        
        avg_time_gap = sum(time_gaps) / len(time_gaps) if time_gaps else 0
        
        # Análisis de valores
        values = [tx.value for tx in transactions if tx.value > 0]
        avg_value = sum(values) / len(values) if values else 0
        
        # Análisis de gas
        gas_prices = [tx.gas_price for tx in transactions]
        avg_gas_price = sum(gas_prices) / len(gas_prices) if gas_prices else 0
        
        # Detección de patrones sospechosos
        suspicious_patterns = []
        
        # Transacciones de alto valor
        high_value_tx = [tx for tx in transactions if tx.value > avg_value * 10]
        if high_value_tx:
            suspicious_patterns.append(f"{len(high_value_tx)} transacciones de alto valor")
        
        # Gas price anómalo
        high_gas_tx = [tx for tx in transactions if tx.gas_price > avg_gas_price * 5]
        if high_gas_tx:
            suspicious_patterns.append(f"{len(high_gas_tx)} transacciones con gas price anómalo")
        
        # Transacciones fallidas
        failed_tx = [tx for tx in transactions if tx.status == 'failed']
        if failed_tx:
            suspicious_patterns.append(f"{len(failed_tx)} transacciones fallidas")
        
        return {
            'total_transactions': len(transactions),
            'avg_time_gap': avg_time_gap,
            'avg_value': avg_value,
            'avg_gas_price': avg_gas_price,
            'suspicious_patterns': suspicious_patterns,
            'high_value_transactions': len(high_value_tx),
            'failed_transactions': len(failed_tx)
        }
    
    def analyze_token_patterns(self, holdings: List[TokenHolding]) -> Dict:
        """Analiza patrones de holdings de tokens"""
        if not holdings:
            return {}
        
        total_value = sum(h.value_usd for h in holdings if h.value_usd > 0)
        high_value_tokens = [h for h in holdings if h.value_usd > 1000]  # >$1000
        
        # Detectar tokens sospechosos
        suspicious_tokens = []
        for holding in holdings:
            if holding.balance > 1000000 and holding.symbol not in ['USDT', 'USDC', 'WETH', 'WBTC']:
                suspicious_tokens.append(holding.symbol)
        
        return {
            'total_tokens': len(holdings),
            'total_value_usd': total_value,
            'high_value_tokens': len(high_value_tokens),
            'suspicious_tokens': suspicious_tokens
        }

# Ejemplo de uso
def demo_blockchain_integration():
    """Demostración de integración blockchain"""
    
    # Nota: Requiere API keys reales para funcionamiento
    etherscan = EtherscanExplorer(api_key="YOUR_ETHERSCAN_API_KEY")
    security_oracle = SecurityOracle()
    analyzer = OnChainAnalyzer(etherscan, security_oracle)
    
    # Ejemplo de análisis
    contract_address = "0x742d35Cc6634C0532925a3b8D4C9db96C4b4Db45"  # Uniswap V2 Router
    
    print(f"Analizando contrato: {contract_address}")
    
    contract_info, transactions, holdings, security_risk = analyzer.analyze_contract(contract_address)
    
    if contract_info:
        print(f"Contrato: {contract_info.name}")
        print(f"Balance: {contract_info.balance} ETH")
        print(f"Transacciones: {contract_info.transaction_count}")
    
    if transactions:
        patterns = analyzer.analyze_transaction_patterns(transactions)
        print(f"Patrones de transacciones: {patterns}")
    
    if holdings:
        token_patterns = analyzer.analyze_token_patterns(holdings)
        print(f"Patrones de tokens: {token_patterns}")
    
    print(f"Riesgo de seguridad: {security_risk.risk_score:.2%}")

if __name__ == "__main__":
    demo_blockchain_integration()
