# Recursos para Contratos Maliciosos de Prueba

## Fuentes Online de Contratos Vulnerables

### 1. Etherscan con Warnings
- **URL**: https://etherscan.io/
- **Cómo buscar**: Filtra por contratos con warnings de seguridad
- **Ejemplo**: Busca contratos marcados con "Warning: Contract Source Code Verified"
- **Keywords**: "honeypot", "rug pull", "vulnerable"

### 2. GitHub - Smart Contract Honeypot Database
- **URL**: https://github.com/misterch0c/shield_honeypot
- **Descripción**: Base de datos de honeypots conocidos
- **Uso**: Copia los contratos para probar tu analyzer

### 3. Smart Contract Weakness Classification (SWC)
- **URL**: https://swcregistry.io/
- **Descripción**: Clasificación oficial de debilidades
- **Contenido**: Ejemplos de código para cada vulnerabilidad

### 4. Immunefi Bug Bounty Reports
- **URL**: https://immunefi.com/
- **Cómo usar**: Lee reportes de bugs públicos
- **Ventaja**: Contratos reales con exploits documentados

### 5. ConsenSys Diligence
- **URL**: https://consensys.github.io/diligence/
- **Contenido**: Reportes de auditoría con vulnerabilidades
- **Ejemplos**: Contratos reales auditados con bugs

## Repositorios GitHub Específicos

### 1. Smart Contract Security Samples
```
https://github.com/sigp/solidity-security-blog
```
- Contratos vulnerables para testing
- Explicaciones detalladas de cada vulnerabilidad

### 2. Ethernaut Game
```
https://github.com/OpenZeppelin/ethernaut
```
- Contratos diseñados para aprender seguridad
- Cada nivel tiene una vulnerabilidad específica

### 3. Damn Vulnerable DeFi
```
https://github.com/tinchoabbate/damn-vulnerable-defi
```
- Contratos DeFi vulnerables
- Simulaciones de ataques reales

### 4. Capture The Ether
```
https://github.com/capturetheether/contracts
```
- Contratos con desafíos de seguridad
- Buena fuente para testing patterns

## Herramientas Online

### 1. Remix IDE
- **URL**: https://remix.ethereum.org/
- **Uso**: Compila y prueba contratos vulnerables
- **Ventaja**: No requiere instalación local

### 2. Tenderly
- **URL**: https://tenderly.co/
- **Características**: Sandbox para testing
- **Beneficio**: Simulación de ataques reales

### 3. Ganache
- **URL**: https://trufflesuite.com/ganache/
- **Uso**: Blockchain local para testing
- **Ventaja**: Testing sin gastar ETH real

## Categorías de Contratos para Testing

### 1. Honeypot Contracts
- Características: Bloquean transferencias
- Patterns: `require(msg.value == 0)`
- Testing: Intenta transferencias con diferentes valores

### 2. Rug Pull Contracts
- Características: Funciones de emergency
- Patterns: `emergencyWithdraw()`, `drainTokens()`
- Testing: Verifica funciones de owner

### 3. Reentrancy Contracts
- Características: Llamadas externas antes de actualizar estado
- Patterns: `.call{value: amount}("")` antes de balance update
- Testing: Simula ataque de reentrada

### 4. Flash Loan Vulnerabilities
- Características: Manipulación de precios
- Patterns: `swap()` sin validación
- Testing: Simula flash loan attack

### 5. MEV Manipulation
- Características: Uso de timestamp/block info
- Patterns: `block.timestamp`, `block.difficulty`
- Testing: Detecta manipulación temporal

## Bases de Datos de Exploits Reales

### 1. DeFi Hack List
- **URL**: https://defihacklist.com/
- **Contenido**: Lista cronológica de hacks
- **Uso**: Estudia patrones de exploits

### 2. Reorg Research
- **URL**: https://reorg.dev/
- **Descripción**: Análisis de exploits DeFi
- **Beneficio**: Contratos reales vulnerables

### 3. Web3 Security
- **URL**: https://web3sec.notion.site/
- **Contenido**: Reportes de seguridad
- **Ventaja**: Análisis técnico detallado

## Cómo Encontrar Contratos Maliciosos

### Método 1: Búsqueda en Etherscan
1. Ve a etherscan.io
2. Busca "honeypot" o "rug pull"
3. Filtra por contratos verificados
4. Copia el código fuente

### Método 2: GitHub Search
1. Busca "solidity honeypot"
2. Filtra por repositorios recientes
3. Revisa el código fuente
4. Prueba con tu analyzer

### Método 3: Reportes de Auditoría
1. Visita sitios de auditoría
2. Lee reportes de bugs
3. Extrae los contratos vulnerables
4. Prueba las detecciones

### Método 4: Competencias de Bug Bounty
1. Reporta de Immunefi
2. Analiza los bugs encontrados
3. Extrae patrones comunes
4. Crea tests específicos

## Contratos de Ejemplo Rápidos

### Honeypot Simple
```solidity
contract Honeypot {
    mapping(address => uint) public balances;
    
    function transfer(address to, uint amount) public {
        require(msg.value == 0, "No ETH allowed"); // Honeypot pattern
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
```

### Rug Pull Simple
```solidity
contract RugPull {
    address public owner;
    mapping(address => uint) public balances;
    
    function emergencyWithdraw() public {
        require(msg.sender == owner); // Rug pull pattern
        payable(owner).transfer(address(this).balance);
    }
}
```

### Reentrancy Simple
```solidity
contract Reentrancy {
    mapping(address => uint) public balances;
    
    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount);
        msg.sender.call{value: amount}(""); // Reentrancy pattern
        balances[msg.sender] -= amount;
    }
}
```

## Tips para Testing Efectivo

### 1. Varía la Complejidad
- Prueba contratos simples y complejos
- Incluye múltiples vulnerabilidades
- Combina diferentes tipos de ataques

### 2. Usa Contratos Reales
- Busca exploits documentados
- Usa contratos de hacks famosos
- Analiza patrones comunes

### 3. Testing Sistemático
- Prueba cada tipo de vulnerabilidad
- Verifica falsos positivos
- Mide la precisión del detector

### 4. Documenta Resultados
- Registra las detecciones
- Compara con resultados esperados
- Mejora los patrones de detección

## Advertencias Importantes

### 1. Uso Ético
- Solo para fines educativos
- No despliegues en mainnet
- No uses para actividades maliciosas

### 2. Seguridad Personal
- Usa wallets de testing
- No uses fondos reales
- Mantén separados los entornos

### 3. Responsabilidad
- El objetivo es mejorar la seguridad
- Comparte conocimientos responsibly
- Contribuye a la comunidad

## Recursos Adicionales

### 1. Libros
- "Mastering Ethereum" - Andreas Antonopoulos
- "Smart Contract Security" - Swende

### 2. Cursos
- Ethereum Smart Contract Security
- DeFi Security Best Practices
- Advanced Solidity Programming

### 3. Comunidades
- Ethereum Security Community
- Smart Contract Auditors Group
- DeFi Security Alliance

Estos recursos te darán acceso a contratos maliciosos reales y simulados para probar exhaustivamente tu Smart Contract Analyzer.
