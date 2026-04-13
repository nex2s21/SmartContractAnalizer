# Ejemplos del Mundo Real - Contratos Maliciosos Históricos

Aquí tienes contratos inteligentes reales que han sido explotados, perfectos para probar el analyzer.

## 1. The DAO Hack (2016) - Reentrancy Attack

```solidity
// Versión simplificada del contrato DAO vulnerable
pragma solidity ^0.4.17;

contract DAO {
    mapping (address => uint) public balances;
    address public owner;
    
    function DAO() {
        owner = msg.sender;
    }
    
    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount);
        
        // VULNERABILIDAD: Llamada externa antes de actualizar balance
        if (msg.sender.call.value(amount)()) {
            balances[msg.sender] -= amount;
        }
    }
    
    function getBalance() public constant returns (uint) {
        return this.balance;
    }
}
```

**Resultado esperado:** Detectará Reentrancy Attack (Crítico)

---

## 2. Parity Wallet Hack (2017) - Selfdestruct

```solidity
// Parity Wallet Library Contract vulnerable
pragma solidity ^0.4.18;

contract WalletLibrary {
    address public owner;
    mapping(address => uint) public balances;
    
    function initWallet(address _owner) public {
        require(owner == 0);
        owner = _owner;
    }
    
    function initWalletAndDeploy(address _owner) public {
        owner = _owner;
    }
    
    // VULNERABILIDAD: Función de suicidio accesible
    function kill() public {
        require(msg.sender == owner);
        selfdestruct(owner);
    }
    
    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        msg.sender.transfer(amount);
    }
}
```

**Resultado esperado:** Detectará Backdoor Function y Selfdestruct (Crítico)

---

## 3. Bancor Network (2018) - Flash Loan Attack

```solidity
// Simplificado del contrato Bancor vulnerable
pragma solidity ^0.4.24;

contract BancorNetwork {
    mapping(address => uint) public tokenBalances;
    address public converter;
    
    function convert(
        address _fromToken,
        address _toToken,
        uint256 _amount,
        uint256 _minReturn
    ) public payable returns (uint256) {
        // VULNERABILIDAD: Flash loan sin validación
        require(msg.value >= _amount);
        
        uint256 returnAmount = calculateReturn(_amount);
        require(returnAmount >= _minReturn);
        
        tokenBalances[msg.sender] += returnAmount;
        return returnAmount;
    }
    
    function calculateReturn(uint amount) internal pure returns (uint) {
        return amount * 2; // Simplificado
    }
}
```

**Resultado esperado:** Detectará Flash Loan Attack (Alto)

---

## 4. bZx Hack (2020) - Price Oracle Manipulation

```solidity
// Contrato bZx vulnerable a manipulación de oráculos
pragma solidity ^0.5.0;

import "./PriceOracle.sol";

contract bZxLoan {
    PriceOracle public oracle;
    mapping(address => uint) public collateral;
    
    function borrow(uint amount) public {
        uint collateralValue = oracle.getPrice("ETH") * collateral[msg.sender];
        uint borrowCapacity = collateralValue / 2;
        
        require(borrowCapacity >= amount, "Insufficient collateral");
        
        // VULNERABILIDAD: Usa oracle sin validación
        msg.sender.transfer(amount);
    }
    
    function manipulateOracle(uint newPrice) public {
        // En el exploit real, manipulaban el precio antes de pedir préstamo
        oracle.setPrice("ETH", newPrice);
    }
}
```

**Resultado esperado:** Detectará MEV Manipulation y Oracle Manipulation (Alto)

---

## 5. Uniswap & SushiSwap Sandwich Attacks

```solidity
// Contrato vulnerable a sandwich attacks
pragma solidity ^0.6.0;

import "@uniswap/v2-core/contracts/interfaces/IUniswapV2Router02.sol";

contract VulnerableDEX {
    IUniswapV2Router02 public router;
    address public token;
    
    function swapTokens(uint amountIn, uint amountOutMin) public {
        // VULNERABILIDAD: No protección contra sandwich attacks
        address[] memory path = new address[](2);
        path[0] = token;
        path[1] = router.WETH();
        
        router.swapExactTokensForETH(
            amountIn,
            amountOutMin,
            path,
            msg.sender,
            block.timestamp + 300
        );
    }
    
    function getAmountOut(uint amountIn) public view returns (uint) {
        // Sin slippage protection
        return amountIn * 95 / 100; // Simplificado
    }
}
```

**Resultado esperado:** Detectará Sandwich Attack (Alto)

---

## 6. DeFi Yield Farming Rug Pulls

```solidity
// Típico contrato de rug pull en DeFi
pragma solidity ^0.6.0;

contract YieldFarmRugPull {
    address public owner;
    mapping(address => uint) public staked;
    mapping(address => uint) public rewards;
    IERC20 public stakingToken;
    IERC20 public rewardToken;
    
    constructor(address _staking, address _reward) public {
        owner = msg.sender;
        stakingToken = IERC20(_staking);
        rewardToken = IERC20(_reward);
    }
    
    function stake(uint amount) public {
        require(amount > 0);
        stakingToken.transferFrom(msg.sender, address(this), amount);
        staked[msg.sender] += amount;
    }
    
    function withdraw() public {
        uint amount = staked[msg.sender];
        require(amount > 0);
        
        staked[msg.sender] = 0;
        rewards[msg.sender] = 0;
        
        stakingToken.transfer(msg.sender, amount);
        rewardToken.transfer(msg.sender, rewards[msg.sender]);
    }
    
    // VULNERABILIDAD: Funciones de rug pull
    function emergencyWithdraw() public {
        require(msg.sender == owner);
        uint balance = stakingToken.balanceOf(address(this));
        stakingToken.transfer(owner, balance);
    }
    
    function drainRewards() public {
        require(msg.sender == owner);
        uint balance = rewardToken.balanceOf(address(this));
        rewardToken.transfer(owner, balance);
    }
    
    function changeOwner(address newOwner) public {
        require(msg.sender == owner);
        owner = newOwner;
    }
}
```

**Resultado esperado:** Detectará Rug Pull y Emergency Functions (Crítico)

---

## 7. NFT Honeypot Contracts

```solidity
// Honeypot de NFT que bloquea transfers
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

contract NFT_Honeypot is ERC721 {
    address public owner;
    mapping(uint256 => bool) public locked;
    
    constructor() ERC721("Honeypot NFT", "HNY") {
        owner = msg.sender;
    }
    
    function transferFrom(address from, address to, uint256 tokenId) public override {
        // VULNERABILIDAD: Bloquea transfers si el valor es alto
        require(tokenId < 100, "Token ID too high");
        require(!locked[tokenId], "Token is locked");
        
        // Honeypot: Solo permite transfers si el remitente es el owner
        require(from == owner || to == owner, "Only owner transfers");
        
        super.transferFrom(from, to, tokenId);
    }
    
    function lockToken(uint256 tokenId) public {
        require(msg.sender == owner);
        locked[tokenId] = true;
    }
    
    function unlockToken(uint256 tokenId) public {
        require(msg.sender == owner);
        locked[tokenId] = false;
    }
}
```

**Resultado esperado:** Detectará Honeypot y Transfer Restrictions (Alto)

---

## 8. Token Contract con Mint Infinito

```solidity
// Contrato de token con mint sin control
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract UnlimitedMintToken is ERC20 {
    address public owner;
    
    constructor() ERC20("Unlimited Token", "ULT") {
        owner = msg.sender;
        _mint(owner, 1000000 * 10**18);
    }
    
    // VULNERABILIDAD: Mint sin límites
    function mint(address to, uint256 amount) public {
        require(msg.sender == owner, "Only owner");
        _mint(to, amount);
    }
    
    function mintToSelf(uint256 amount) public {
        require(msg.sender == owner, "Only owner");
        _mint(msg.sender, amount);
    }
    
    // Backdoor: Mint para cualquier dirección
    function backdoorMint(uint256 amount) public {
        _mint(msg.sender, amount);
    }
}
```

**Resultado esperado:** Detectará Unlimited Mint y Backdoor Function (Alto)

---

## 9. Phishing Contract con Approve Malicioso

```solidity
// Contrato de phishing que roba approvals
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract TokenPhishing {
    address public owner;
    IERC20 public targetToken;
    
    constructor(address _token) {
        owner = msg.sender;
        targetToken = IERC20(_token);
    }
    
    // VULNERABILIDAD: Función de phishing
    function approveAndClaim(uint256 amount) public {
        // Parece una función legítima pero roba los approvals
        targetToken.transferFrom(msg.sender, owner, amount);
    }
    
    function claimAirdrop(uint256 amount) public {
        // Falso airdrop que requiere approve
        targetToken.transferFrom(msg.sender, owner, amount);
    }
    
    function stakeTokens(uint256 amount) public {
        // Falso staking que transfiere tokens al owner
        targetToken.transferFrom(msg.sender, owner, amount);
    }
    
    function withdrawStaked(uint256 amount) public {
        require(msg.sender == owner, "Only owner");
        targetToken.transfer(owner, amount);
    }
}
```

**Resultado esperado:** Detectará Phishing Pattern y Malicious Approvals (Crítico)

---

## 10. Gas Griefing Contract

```solidity
// Contrato que realiza gas griefing
pragma solidity ^0.8.0;

contract GasGriefing {
    mapping(address => uint) public balances;
    bool public emergency;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    function expensiveWithdraw(uint amount) public {
        require(balances[msg.sender] >= amount);
        
        // VULNERABILIDAD: Consumo excesivo de gas
        for (uint i = 0; i < 10000; i++) {
            balances[msg.sender] = i;
        }
        
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
    
    function gasGriefingAttack() public payable {
        // Ataque de gas griefing
        uint gasStart = gasleft();
        
        while (gasleft() > 100000) {
            // Consumir gas innecesariamente
            emergency = !emergency;
        }
    }
    
    function blockTimestampManipulation() public view returns (uint) {
        // Manipulación de timestamp
        return block.timestamp % 100;
    }
}
```

**Resultado esperado:** Detectará Gas Anomalies y Timestamp Manipulation (Medio)

---

## Cómo Probar Estos Contratos

1. **Selecciona un contrato** de la lista
2. **Copia el código** completo
3. **Pégalo en el Smart Contract Analyzer**
4. **Haz clic en "Analizar Contrato"**
5. **Observa las detecciones** en cada pestaña

## Resultados Esperados por Tipo

| Tipo de Contrato | Vulnerabilidades Detectadas | Severidad |
|------------------|-----------------------------|-----------|
| The DAO Hack | Reentrancy Attack | Crítico |
| Parity Wallet | Selfdestruct, Backdoor | Crítico |
| Bancor Network | Flash Loan Attack | Alto |
| bZx Hack | MEV Manipulation, Oracle Manipulation | Alto |
| Sandwich Attack | Sandwich Attack, Frontrunning | Alto |
| Rug Pull | Rug Pull, Emergency Functions | Crítico |
| NFT Honeypot | Honeypot, Transfer Restrictions | Alto |
| Unlimited Mint | Unlimited Mint, Backdoor | Alto |
| Phishing | Phishing, Malicious Approvals | Crítico |
| Gas Griefing | Gas Anomalies, Timestamp Manipulation | Medio |

## Fuentes de Contratos Reales

Para obtener más contratos reales:

1. **Etherscan** - Busca contratos con warnings
2. **Dune Analytics** - Analiza exploits históricos
3. **Immunefi** - Reportes de bugs reales
4. **ConsenSys Audit Reports** - Contratos auditados con vulnerabilidades
5. **GitHub Security Advisories** - Vulnerabilidades reportadas

## Advertencia Importante

Estos contratos son **solo para fines educativos y testing**. No los despliegues en mainnet ni los uses para actividades maliciosas. El objetivo es mejorar la seguridad, no explotar vulnerabilidades.
