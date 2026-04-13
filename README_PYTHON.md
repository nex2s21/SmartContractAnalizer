# Smart Contract Analyzer - Enhanced Version (Python)

## Descripción

Versión mejorada del analizador de contratos inteligentes escrita en Python con interfaz gráfica nativa. Esta versión es mucho más fácil de instalar y distribuir que la versión original en Rust.

## Características Principales

### 50+ Patrones de Detección Avanzados

- **Honeypot Detection** - Bloqueo de transferencias malicioso
- **Rug Pull Analysis** - Manipulación de ownership
- **Phishing Pattern Recognition** - Aprobaciones maliciosas
- **Flash Loan Attack Detection** - Vulnerabilidades de flash loans
- **MEV Manipulation Analysis** - Manipulación de mercado
- **Sandwich Attack Detection** - Frontrunning y sandwich attacks
- **Backdoor Function Detection** - Funciones ocultas y backdoors
- **Reentrancy Attack Detection** - Ataques de reentrada
- **Unlimited Mint Detection** - Mint infinito de tokens
- **Blacklist Function Detection** - Listas negras y exclusiones

### Machine Learning Integration

- **Feature Extraction** - 15 métricas de análisis
- **Risk Scoring** - Puntuación de riesgo automática
- **Scam Type Classification** - Clasificación inteligente de scams
- **Confidence Scoring** - Nivel de confianza en la predicción

### Análisis Comportamental

- **Transaction Pattern Analysis** - Patrones de transacción sospechosos
- **Gas Anomaly Detection** - Anomalías en el uso de gas
- **Timing Analysis** - Anomalías temporales
- **Behavioral Risk Assessment** - Evaluación de riesgo comportamental

### Interfaz Gráfica Moderna

- **Tkinter GUI** - Interfaz nativa de Python
- **Multi-tab Interface** - Organización clara de resultados
- **Real-time Analysis** - Análisis en tiempo real
- **File Loading** - Carga de archivos .sol
- **Example Contracts** - Ejemplos de contratos vulnerables

## Instalación

### Método 1: Ejecutable (.exe) - Recomendado

1. Descarga el archivo `SmartContractAnalyzer.exe` de la carpeta `dist`
2. Ejecuta directamente el archivo .exe
3. No requiere instalación de Python ni dependencias

### Método 2: Script de Instalación Automática

1. Ejecuta `install.bat`
2. El script verificará Python e instalará las dependencias
3. Iniciará automáticamente el programa

### Método 3: Manual (para desarrolladores)

1. Asegúrate de tener Python 3.8+ instalado
2. Instala las dependencias:
   ```bash
   pip install -r requirements.txt
   ```
3. Ejecuta el programa:
   ```bash
   python smart_contract_analyzer.py
   ```

## Uso

### Análisis Básico

1. **Pega el código** del contrato inteligente en el área de texto
2. **Haz clic en "Analizar Contrato"**
3. **Revisa los resultados** en las diferentes pestañas:
   - **Hallazgos de Seguridad** - Vulnerabilidades detectadas
   - **Análisis ML** - Predicciones de machine learning
   - **Análisis Comportamental** - Patrones sospechosos

### Características Adicionales

- **Cargar Archivo** - Importa archivos .sol directamente
- **Ejemplo** - Carga un contrato vulnerable de ejemplo
- **Limpiar** - Limpia todo el contenido para un nuevo análisis

## Ejemplo de Uso

```solidity
// Ejemplo de contrato vulnerable
pragma solidity ^0.8.0;

contract VulnerableContract {
    address public owner;
    mapping(address => uint) public balances;
    
    constructor() {
        owner = msg.sender;
    }
    
    // Vulnerabilidad: Reentrancy
    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;  // Estado actualizado después del call
    }
}
```

Este contrato será detectado como vulnerable con:
- **Reentrancy Attack** (Alto riesgo)
- **Risk Score ML**: ~75%
- **Patrones comportamentales**: Transferencias sospechosas

## Salida del Análisis

### Hallazgos de Seguridad
```
Alto:
  Reentrancy Attack - Ataque de Reentrada
  Línea: 15
  Código: (bool success, ) = msg.sender.call{value: amount}("");
  Descripción: Patrón sospechoso detectado: reentrancy_vulnerable
  Recomendación: Usar pattern checks-effects-interactions y ReentrancyGuard.
```

### Análisis ML
```
Risk Score: 75.00%
Confidence: 95.00%
Scam Type: Reentrancy Attack

Análisis ML muestra riesgo del 75.00% basado en:
- external_calls: 80.00%
- code_complexity: 40.00%
- function_count: 30.00%
```

### Análisis Comportamental
```
Transaction Risk: 60.00%

Patrones Sospechosos:
  - Múltiples transferencias
  - Transacción sin valor requerida

Anomalías de Gas:
  - Manipulación de gas detectada
```

## Ventajas sobre la Versión Rust

### Facilidad de Instalación
- **Python**: Preinstalado en la mayoría de sistemas
- **Sin compiladores**: No necesita Visual Studio ni linkers
- **Ejecutable único**: Un solo archivo .exe con todo incluido

### Portabilidad
- **Windows**: Ejecutable .exe nativo
- **Linux/Mac**: Compatible con Python estándar
- **Menor tamaño**: ~12MB vs 50MB+ de la versión Rust

### Mantenimiento
- **Código más simple**: Python es más fácil de leer y modificar
- **Menos dependencias**: Solo requests y tkinter
- **Desarrollo rápido**: Iteración más rápida de features

## Arquitectura del Código

### Módulos Principales

- **SecurityAnalyzer** - Analizador principal de seguridad
- **MLScamDetector** - Motor de machine learning
- **BehavioralAnalyzer** - Análisis de patrones comportamentales
- **SmartContractAnalyzerGUI** - Interfaz gráfica principal

### Estructura de Datos

- **Finding** - Estructura de hallazgos de seguridad
- **MLAnalysisResult** - Resultados del análisis ML
- **BehavioralAnalysisResult** - Resultados comportamentales
- **Severity/ScamType** - Enums de clasificación

## Rendimiento

- **Análisis rápido**: <1 segundo para contratos típicos
- **Bajo consumo de memoria**: <50MB RAM
- **Multi-threading**: Análisis en background sin bloquear UI

## Seguridad y Privacidad

- **Análisis local**: Todo el procesamiento se realiza localmente
- **Sin datos externos**: No envía código a servidores
- **Código abierto**: Totalmente auditable y transparente

## Contribución

Este proyecto es de código abierto. Para contribuir:

1. Fork del repositorio
2. Crear una feature branch
3. Implementar nuevas funcionalidades
4. Enviar pull request

## Licencia

MIT License - Ver archivo LICENSE para detalles

## Soporte

Para problemas o preguntas:
- Revisa este README
- Abre un issue en el repositorio
- Contacta al desarrollador

---

**Versión:** 2.0.0 (Python Enhanced)  
**Última actualización:** 2026-04-13  
**Desarrollador:** Smart Contract Analyzer Team
