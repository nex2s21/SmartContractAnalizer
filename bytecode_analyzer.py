#!/usr/bin/env python3
"""
Advanced Bytecode Analyzer
Análisis avanzado de bytecode de contratos inteligentes
"""

import re
import json
import struct
import binascii
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import hashlib

class Opcode(Enum):
    """Opcodes de Ethereum EVM"""
    STOP = 0x00
    ADD = 0x01
    MUL = 0x02
    SUB = 0x03
    DIV = 0x04
    SDIV = 0x05
    MOD = 0x06
    SMOD = 0x07
    ADDMOD = 0x08
    MULMOD = 0x09
    EXP = 0x0a
    SIGNEXTEND = 0x0b
    LT = 0x10
    GT = 0x11
    SLT = 0x12
    SGT = 0x13
    EQ = 0x14
    ISZERO = 0x15
    AND = 0x16
    OR = 0x17
    XOR = 0x18
    NOT = 0x19
    BYTE = 0x1a
    SHL = 0x1b
    SHR = 0x1c
    SAR = 0x1d
    SHA3 = 0x20
    ADDRESS = 0x30
    BALANCE = 0x31
    ORIGIN = 0x32
    CALLER = 0x33
    CALLVALUE = 0x34
    CALLDATALOAD = 0x35
    CALLDATASIZE = 0x36
    CALLDATACOPY = 0x37
    CODESIZE = 0x38
    CODECOPY = 0x39
    GASPRICE = 0x3a
    EXTCODESIZE = 0x3b
    EXTCODECOPY = 0x3c
    RETURNDATASIZE = 0x3d
    RETURNDATACOPY = 0x3e
    BLOCKHASH = 0x40
    COINBASE = 0x41
    TIMESTAMP = 0x42
    NUMBER = 0x43
    DIFFICULTY = 0x44
    GASLIMIT = 0x45
    CHAINID = 0x46
    SELFBALANCE = 0x47
    BASEFEE = 0x48
    POP = 0x50
    MLOAD = 0x51
    MSTORE = 0x52
    MSTORE8 = 0x53
    SLOAD = 0x54
    SSTORE = 0x55
    JUMP = 0x56
    JUMPI = 0x57
    PC = 0x58
    MSIZE = 0x59
    GAS = 0x5a
    JUMPDEST = 0x5b
    PUSH1 = 0x60
    PUSH2 = 0x61
    PUSH3 = 0x62
    PUSH4 = 0x63
    PUSH5 = 0x64
    PUSH6 = 0x65
    PUSH7 = 0x66
    PUSH8 = 0x67
    PUSH9 = 0x68
    PUSH10 = 0x69
    PUSH11 = 0x6a
    PUSH12 = 0x6b
    PUSH13 = 0x6c
    PUSH14 = 0x6d
    PUSH15 = 0x6e
    PUSH16 = 0x6f
    PUSH17 = 0x70
    PUSH18 = 0x71
    PUSH19 = 0x72
    PUSH20 = 0x73
    PUSH21 = 0x74
    PUSH22 = 0x75
    PUSH23 = 0x76
    PUSH24 = 0x77
    PUSH25 = 0x78
    PUSH26 = 0x79
    PUSH27 = 0x7a
    PUSH28 = 0x7b
    PUSH29 = 0x7c
    PUSH30 = 0x7d
    PUSH31 = 0x7e
    PUSH32 = 0x7f
    DUP1 = 0x80
    DUP2 = 0x81
    DUP3 = 0x82
    DUP4 = 0x83
    DUP5 = 0x84
    DUP6 = 0x85
    DUP7 = 0x86
    DUP8 = 0x87
    DUP9 = 0x88
    DUP10 = 0x89
    DUP11 = 0x8a
    DUP12 = 0x8b
    DUP13 = 0x8c
    DUP14 = 0x8d
    DUP15 = 0x8e
    DUP16 = 0x8f
    SWAP1 = 0x90
    SWAP2 = 0x91
    SWAP3 = 0x92
    SWAP4 = 0x93
    SWAP5 = 0x94
    SWAP6 = 0x95
    SWAP7 = 0x96
    SWAP8 = 0x97
    SWAP9 = 0x98
    SWAP10 = 0x99
    SWAP11 = 0x9a
    SWAP12 = 0x9b
    SWAP13 = 0x9c
    SWAP14 = 0x9d
    SWAP15 = 0x9e
    SWAP16 = 0x9f
    LOG0 = 0xa0
    LOG1 = 0xa1
    LOG2 = 0xa2
    LOG3 = 0xa3
    LOG4 = 0xa4
    CREATE = 0xf0
    CALL = 0xf1
    CALLCODE = 0xf2
    RETURN = 0xf3
    DELEGATECALL = 0xf4
    CREATE2 = 0xf5
    STATICCALL = 0xfa
    REVERT = 0xfd
    INVALID = 0xfe
    SELFDESTRUCT = 0xff

@dataclass
class BytecodeInstruction:
    """Instrucción de bytecode"""
    opcode: Opcode
    pc: int
    operand: Optional[bytes]
    operand_value: Optional[int]
    description: str

@dataclass
class BytecodePattern:
    """Patrón detectado en bytecode"""
    name: str
    description: str
    severity: str
    pc_start: int
    pc_end: int
    instructions: List[BytecodeInstruction]
    risk_score: float

class BytecodeAnalyzer:
    """Analizador avanzado de bytecode"""
    
    def __init__(self):
        self.opcode_names = {op.value: op.name for op in Opcode}
        self.opcode_values = {op.name: op.value for op in Opcode}
        self.setup_patterns()
    
    def setup_patterns(self):
        """Configura patrones de detección en bytecode"""
        self.patterns = {
            'selfdestruct': [
                [Opcode.SELFDESTRUCT.value],
                [Opcode.PUSH1, Opcode.SELFDESTRUCT],
                [Opcode.PUSH2, Opcode.SELFDESTRUCT]
            ],
            'delegatecall': [
                [Opcode.DELEGATECALL.value],
                [Opcode.PUSH1, Opcode.DELEGATECALL],
                [Opcode.PUSH2, Opcode.DELEGATECALL]
            ],
            'call_with_value': [
                [Opcode.CALL.value],
                [Opcode.PUSH1, Opcode.CALL],
                [Opcode.PUSH2, Opcode.CALL]
            ],
            'staticcall': [
                [Opcode.STATICCALL.value],
                [Opcode.PUSH1, Opcode.STATICCALL],
                [Opcode.PUSH2, Opcode.STATICCALL]
            ],
            'create_contract': [
                [Opcode.CREATE.value],
                [Opcode.CREATE2.value]
            ],
            'block_timestamp_dependency': [
                [Opcode.TIMESTAMP.value],
                [Opcode.PUSH1, Opcode.TIMESTAMP],
                [Opcode.TIMESTAMP, Opcode.LT],
                [Opcode.TIMESTAMP, Opcode.GT]
            ],
            'block_difficulty_dependency': [
                [Opcode.DIFFICULTY.value],
                [Opcode.PUSH1, Opcode.DIFFICULTY],
                [Opcode.DIFFICULTY, Opcode.LT],
                [Opcode.DIFFICULTY, Opcode.GT]
            ],
            'origin_dependency': [
                [Opcode.ORIGIN.value],
                [Opcode.PUSH1, Opcode.ORIGIN],
                [Opcode.ORIGIN, Opcode.EQ]
            ],
            'caller_check_bypass': [
                [Opcode.CALLER.value],
                [Opcode.ORIGIN.value],
                [Opcode.CALLER, Opcode.EQ, Opcode.JUMPI]
            ],
            'gas_manipulation': [
                [Opcode.GAS.value],
                [Opcode.GASLIMIT.value],
                [Opcode.GASPRICE.value]
            ],
            'storage_manipulation': [
                [Opcode.SSTORE.value],
                [Opcode.SLOAD.value, Opcode.SSTORE]
            ],
            'memory_manipulation': [
                [Opcode.MSTORE.value],
                [Opcode.MLOAD.value],
                [Opcode.MSTORE8.value]
            ],
            'hash_operations': [
                [Opcode.SHA3.value],
                [Opcode.BLOCKHASH.value]
            ],
            'arithmetic_overflow': [
                [Opcode.ADD.value, Opcode.ADD.value],
                [Opcode.MUL.value, Opcode.MUL.value],
                [Opcode.EXP.value]
            ],
            'unconditional_jump': [
                [Opcode.JUMP.value],
                [Opcode.PUSH1, Opcode.JUMP]
            ],
            'conditional_jump_manipulation': [
                [Opcode.JUMPI.value],
                [Opcode.PUSH1, Opcode.JUMPI]
            ]
        }
    
    def parse_bytecode(self, bytecode: str) -> List[BytecodeInstruction]:
        """Parsea bytecode a instrucciones"""
        if bytecode.startswith('0x'):
            bytecode = bytecode[2:]
        
        instructions = []
        pc = 0
        i = 0
        n = len(bytecode)
        
        while i < n:
            if i + 2 > n:
                break
                
            opcode_byte = int(bytecode[i:i+2], 16)
            opcode = Opcode(opcode_byte) if opcode_byte in [op.value for op in Opcode] else Opcode.INVALID
            
            operand = None
            operand_value = None
            description = self.opcode_names.get(opcode_byte, f"UNKNOWN_{opcode_byte:02x}")
            
            # Handle PUSH instructions
            if Opcode.PUSH1.value <= opcode_byte <= Opcode.PUSH32.value:
                push_bytes = opcode_byte - Opcode.PUSH1.value + 1
                if i + 2 + push_bytes * 2 > n:
                    break
                
                operand_hex = bytecode[i+2:i+2+push_bytes*2]
                operand = bytes.fromhex(operand_hex)
                operand_value = int(operand_hex, 16) if operand_hex else 0
                description = f"{description} 0x{operand_hex}"
                i += 2 + push_bytes * 2
            else:
                i += 2
            
            instruction = BytecodeInstruction(
                opcode=opcode,
                pc=pc,
                operand=operand,
                operand_value=operand_value,
                description=description
            )
            
            instructions.append(instruction)
            pc += 1
        
        return instructions
    
    def analyze_patterns(self, instructions: List[BytecodeInstruction]) -> List[BytecodePattern]:
        """Analiza patrones en las instrucciones"""
        patterns_found = []
        
        for pattern_name, pattern_sequences in self.patterns.items():
            for sequence in pattern_sequences:
                matches = self._find_pattern_sequence(instructions, sequence)
                for match in matches:
                    pattern = BytecodePattern(
                        name=pattern_name,
                        description=self._get_pattern_description(pattern_name),
                        severity=self._get_pattern_severity(pattern_name),
                        pc_start=match[0],
                        pc_end=match[1],
                        instructions=instructions[match[0]:match[1]+1],
                        risk_score=self._calculate_pattern_risk(pattern_name)
                    )
                    patterns_found.append(pattern)
        
        return patterns_found
    
    def _find_pattern_sequence(self, instructions: List[BytecodeInstruction], sequence: List[int]) -> List[Tuple[int, int]]:
        """Encuentra secuencias de patrones"""
        matches = []
        
        for i in range(len(instructions) - len(sequence) + 1):
            found = True
            for j, opcode_val in enumerate(sequence):
                if i+j >= len(instructions) or instructions[i+j].opcode.value != opcode_val:
                    found = False
                    break
            
            if found:
                matches.append((i, i + len(sequence) - 1))
        
        return matches
    
    def _get_pattern_description(self, pattern_name: str) -> str:
        """Obtiene descripción del patrón"""
        descriptions = {
            'selfdestruct': 'Selfdestruct detected - Contract can be destroyed',
            'delegatecall': 'Delegatecall detected - Potential storage collision risk',
            'call_with_value': 'CALL with value detected - Potential reentrancy risk',
            'staticcall': 'Staticcall detected - External call without state change',
            'create_contract': 'Contract creation detected',
            'block_timestamp_dependency': 'Block timestamp dependency - Predictable randomness',
            'block_difficulty_dependency': 'Block difficulty dependency - Predictable randomness',
            'origin_dependency': 'tx.origin dependency - Authorization bypass risk',
            'caller_check_bypass': 'Potential caller check bypass',
            'gas_manipulation': 'Gas manipulation detected',
            'storage_manipulation': 'Storage manipulation detected',
            'memory_manipulation': 'Memory manipulation detected',
            'hash_operations': 'Hash operations detected',
            'arithmetic_overflow': 'Potential arithmetic overflow',
            'unconditional_jump': 'Unconditional jump detected',
            'conditional_jump_manipulation': 'Conditional jump manipulation'
        }
        return descriptions.get(pattern_name, f"Pattern: {pattern_name}")
    
    def _get_pattern_severity(self, pattern_name: str) -> str:
        """Determina severidad del patrón"""
        severity_map = {
            'selfdestruct': 'Critical',
            'delegatecall': 'High',
            'call_with_value': 'High',
            'staticcall': 'Medium',
            'create_contract': 'Medium',
            'block_timestamp_dependency': 'Medium',
            'block_difficulty_dependency': 'Medium',
            'origin_dependency': 'High',
            'caller_check_bypass': 'High',
            'gas_manipulation': 'Medium',
            'storage_manipulation': 'Medium',
            'memory_manipulation': 'Low',
            'hash_operations': 'Low',
            'arithmetic_overflow': 'High',
            'unconditional_jump': 'Medium',
            'conditional_jump_manipulation': 'High'
        }
        return severity_map.get(pattern_name, 'Medium')
    
    def _calculate_pattern_risk(self, pattern_name: str) -> float:
        """Calcula riesgo del patrón"""
        risk_scores = {
            'selfdestruct': 0.95,
            'delegatecall': 0.80,
            'call_with_value': 0.75,
            'staticcall': 0.40,
            'create_contract': 0.50,
            'block_timestamp_dependency': 0.60,
            'block_difficulty_dependency': 0.60,
            'origin_dependency': 0.85,
            'caller_check_bypass': 0.80,
            'gas_manipulation': 0.55,
            'storage_manipulation': 0.45,
            'memory_manipulation': 0.30,
            'hash_operations': 0.35,
            'arithmetic_overflow': 0.70,
            'unconditional_jump': 0.50,
            'conditional_jump_manipulation': 0.65
        }
        return risk_scores.get(pattern_name, 0.50)
    
    def analyze_control_flow(self, instructions: List[BytecodeInstruction]) -> Dict:
        """Analiza flujo de control"""
        jumps = []
        jumpdests = []
        calls = []
        creates = []
        
        for i, instruction in enumerate(instructions):
            if instruction.opcode in [Opcode.JUMP, Opcode.JUMPI]:
                jumps.append(i)
            elif instruction.opcode == Opcode.JUMPDEST:
                jumpdests.append(i)
            elif instruction.opcode in [Opcode.CALL, Opcode.DELEGATECALL, Opcode.STATICCALL]:
                calls.append(i)
            elif instruction.opcode in [Opcode.CREATE, Opcode.CREATE2]:
                creates.append(i)
        
        return {
            'total_instructions': len(instructions),
            'jumps': jumps,
            'jumpdests': jumpdests,
            'calls': calls,
            'creates': creates,
            'jump_density': len(jumps) / len(instructions) if instructions else 0,
            'call_density': len(calls) / len(instructions) if instructions else 0,
            'complexity_score': self._calculate_complexity(instructions)
        }
    
    def _calculate_complexity(self, instructions: List[BytecodeInstruction]) -> float:
        """Calcula complejidad del bytecode"""
        complexity = 0.0
        
        # Ponderar diferentes tipos de instrucciones
        for instruction in instructions:
            if instruction.opcode in [Opcode.JUMP, Opcode.JUMPI]:
                complexity += 2.0
            elif instruction.opcode in [Opcode.CALL, Opcode.DELEGATECALL, Opcode.STATICCALL]:
                complexity += 1.5
            elif instruction.opcode in [Opcode.CREATE, Opcode.CREATE2]:
                complexity += 2.0
            elif instruction.opcode in [Opcode.SSTORE, Opcode.MSTORE]:
                complexity += 1.0
            elif instruction.opcode in [Opcode.SHA3, Opcode.BLOCKHASH]:
                complexity += 1.2
            else:
                complexity += 0.5
        
        return min(complexity / len(instructions), 1.0) if instructions else 0.0
    
    def analyze_gas_usage(self, instructions: List[BytecodeInstruction]) -> Dict:
        """Analiza consumo de gas"""
        gas_costs = {
            Opcode.STOP: 0,
            Opcode.ADD: 3,
            Opcode.MUL: 5,
            Opcode.SUB: 3,
            Opcode.DIV: 5,
            Opcode.SDIV: 5,
            Opcode.MOD: 5,
            Opcode.SMOD: 5,
            Opcode.ADDMOD: 8,
            Opcode.MULMOD: 8,
            Opcode.EXP: 50,
            Opcode.SIGNEXTEND: 5,
            Opcode.LT: 3,
            Opcode.GT: 3,
            Opcode.SLT: 3,
            Opcode.SGT: 3,
            Opcode.EQ: 3,
            Opcode.ISZERO: 3,
            Opcode.AND: 3,
            Opcode.OR: 3,
            Opcode.XOR: 3,
            Opcode.NOT: 3,
            Opcode.BYTE: 3,
            Opcode.SHL: 3,
            Opcode.SHR: 3,
            Opcode.SAR: 3,
            Opcode.SHA3: 30,
            Opcode.ADDRESS: 2,
            Opcode.BALANCE: 400,
            Opcode.ORIGIN: 2,
            Opcode.CALLER: 2,
            Opcode.CALLVALUE: 2,
            Opcode.CALLDATALOAD: 3,
            Opcode.CALLDATASIZE: 2,
            Opcode.CALLDATACOPY: 3,
            Opcode.CODESIZE: 2,
            Opcode.CODECOPY: 3,
            Opcode.GASPRICE: 2,
            Opcode.EXTCODESIZE: 700,
            Opcode.EXTCODECOPY: 700,
            Opcode.RETURNDATASIZE: 2,
            Opcode.RETURNDATACOPY: 3,
            Opcode.BLOCKHASH: 20,
            Opcode.COINBASE: 2,
            Opcode.TIMESTAMP: 2,
            Opcode.NUMBER: 2,
            Opcode.DIFFICULTY: 2,
            Opcode.GASLIMIT: 2,
            Opcode.CHAINID: 2,
            Opcode.SELFBALANCE: 0,
            Opcode.BASEFEE: 2,
            Opcode.POP: 2,
            Opcode.MLOAD: 3,
            Opcode.MSTORE: 3,
            Opcode.MSTORE8: 3,
            Opcode.SLOAD: 800,
            Opcode.SSTORE: 20000,
            Opcode.JUMP: 8,
            Opcode.JUMPI: 10,
            Opcode.PC: 2,
            Opcode.MSIZE: 2,
            Opcode.GAS: 2,
            Opcode.JUMPDEST: 1,
            Opcode.PUSH1: 3,
            Opcode.PUSH2: 3,
            Opcode.PUSH3: 3,
            Opcode.PUSH4: 3,
            Opcode.PUSH5: 3,
            Opcode.PUSH6: 3,
            Opcode.PUSH7: 3,
            Opcode.PUSH8: 3,
            Opcode.PUSH9: 3,
            Opcode.PUSH10: 3,
            Opcode.PUSH11: 3,
            Opcode.PUSH12: 3,
            Opcode.PUSH13: 3,
            Opcode.PUSH14: 3,
            Opcode.PUSH15: 3,
            Opcode.PUSH16: 3,
            Opcode.PUSH17: 3,
            Opcode.PUSH18: 3,
            Opcode.PUSH19: 3,
            Opcode.PUSH20: 3,
            Opcode.PUSH21: 3,
            Opcode.PUSH22: 3,
            Opcode.PUSH23: 3,
            Opcode.PUSH24: 3,
            Opcode.PUSH25: 3,
            Opcode.PUSH26: 3,
            Opcode.PUSH27: 3,
            Opcode.PUSH28: 3,
            Opcode.PUSH29: 3,
            Opcode.PUSH30: 3,
            Opcode.PUSH31: 3,
            Opcode.PUSH32: 3,
            Opcode.DUP1: 3,
            Opcode.DUP2: 3,
            Opcode.DUP3: 3,
            Opcode.DUP4: 3,
            Opcode.DUP5: 3,
            Opcode.DUP6: 3,
            Opcode.DUP7: 3,
            Opcode.DUP8: 3,
            Opcode.DUP9: 3,
            Opcode.DUP10: 3,
            Opcode.DUP11: 3,
            Opcode.DUP12: 3,
            Opcode.DUP13: 3,
            Opcode.DUP14: 3,
            Opcode.DUP15: 3,
            Opcode.DUP16: 3,
            Opcode.SWAP1: 3,
            Opcode.SWAP2: 3,
            Opcode.SWAP3: 3,
            Opcode.SWAP4: 3,
            Opcode.SWAP5: 3,
            Opcode.SWAP6: 3,
            Opcode.SWAP7: 3,
            Opcode.SWAP8: 3,
            Opcode.SWAP9: 3,
            Opcode.SWAP10: 3,
            Opcode.SWAP11: 3,
            Opcode.SWAP12: 3,
            Opcode.SWAP13: 3,
            Opcode.SWAP14: 3,
            Opcode.SWAP15: 3,
            Opcode.SWAP16: 3,
            Opcode.LOG0: 750,
            Opcode.LOG1: 1140,
            Opcode.LOG2: 1530,
            Opcode.LOG3: 1920,
            Opcode.LOG4: 2310,
            Opcode.CREATE: 32000,
            Opcode.CALL: 700,
            Opcode.CALLCODE: 700,
            Opcode.RETURN: 0,
            Opcode.DELEGATECALL: 700,
            Opcode.CREATE2: 32000,
            Opcode.STATICCALL: 700,
            Opcode.REVERT: 0,
            Opcode.INVALID: 0,
            Opcode.SELFDESTRUCT: 5000
        }
        
        total_gas = 0
        expensive_operations = []
        
        for instruction in instructions:
            gas_cost = gas_costs.get(instruction.opcode, 0)
            total_gas += gas_cost
            
            if gas_cost > 1000:
                expensive_operations.append({
                    'pc': instruction.pc,
                    'opcode': instruction.opcode.name,
                    'gas_cost': gas_cost,
                    'description': instruction.description
                })
        
        return {
            'total_gas': total_gas,
            'average_gas_per_instruction': total_gas / len(instructions) if instructions else 0,
            'expensive_operations': expensive_operations,
            'gas_efficiency': self._calculate_gas_efficiency(instructions, total_gas)
        }
    
    def _calculate_gas_efficiency(self, instructions: List[BytecodeInstruction], total_gas: int) -> float:
        """Calcula eficiencia de gas"""
        if not instructions:
            return 1.0
        
        # Operaciones de alto costo
        high_cost_ops = [Opcode.SSTORE, Opcode.CREATE, Opcode.CREATE2, Opcode.CALL, Opcode.DELEGATECALL]
        high_cost_count = sum(1 for inst in instructions if inst.opcode in high_cost_ops)
        
        # Operaciones de bajo costo
        low_cost_ops = [Opcode.ADD, Opcode.SUB, Opcode.MUL, Opcode.DIV, Opcode.AND, Opcode.OR, Opcode.XOR]
        low_cost_count = sum(1 for inst in instructions if inst.opcode in low_cost_ops)
        
        # Eficiencia basada en proporción de operaciones de bajo costo
        efficiency = low_cost_count / len(instructions) if instructions else 0
        
        # Penalizar demasiadas operaciones de alto costo
        if high_cost_count / len(instructions) > 0.3:
            efficiency *= 0.7
        
        return min(efficiency, 1.0)
    
    def analyze_bytecode(self, bytecode: str) -> Dict:
        """Análisis completo de bytecode"""
        instructions = self.parse_bytecode(bytecode)
        patterns = self.analyze_patterns(instructions)
        control_flow = self.analyze_control_flow(instructions)
        gas_analysis = self.analyze_gas_usage(instructions)
        
        # Calcular riesgo general
        risk_score = self._calculate_overall_risk(patterns, control_flow, gas_analysis)
        
        return {
            'bytecode_length': len(bytecode),
            'instructions_count': len(instructions),
            'patterns': patterns,
            'control_flow': control_flow,
            'gas_analysis': gas_analysis,
            'overall_risk_score': risk_score,
            'risk_level': self._get_risk_level(risk_score),
            'recommendations': self._generate_recommendations(patterns, control_flow, gas_analysis)
        }
    
    def _calculate_overall_risk(self, patterns: List[BytecodePattern], control_flow: Dict, gas_analysis: Dict) -> float:
        """Calcula riesgo general"""
        # Riesgo de patrones
        pattern_risk = sum(p.risk_score for p in patterns) / len(patterns) if patterns else 0
        
        # Riesgo de complejidad
        complexity_risk = control_flow['complexity_score']
        
        # Riesgo de operaciones costosas
        expensive_risk = len(gas_analysis['expensive_operations']) / 100  # Normalizado
        
        # Ponderación
        overall_risk = (pattern_risk * 0.5 + complexity_risk * 0.3 + expensive_risk * 0.2)
        
        return min(overall_risk, 1.0)
    
    def _get_risk_level(self, risk_score: float) -> str:
        """Determina nivel de riesgo"""
        if risk_score >= 0.8:
            return "Critical"
        elif risk_score >= 0.6:
            return "High"
        elif risk_score >= 0.4:
            return "Medium"
        elif risk_score >= 0.2:
            return "Low"
        else:
            return "Info"
    
    def _generate_recommendations(self, patterns: List[BytecodePattern], control_flow: Dict, gas_analysis: Dict) -> List[str]:
        """Genera recomendaciones"""
        recommendations = []
        
        # Recomendaciones basadas en patrones
        pattern_names = [p.name for p in patterns]
        
        if 'selfdestruct' in pattern_names:
            recommendations.append("Remove selfdestruct functionality or implement strict access controls")
        
        if 'delegatecall' in pattern_names:
            recommendations.append("Use delegatecall with caution and implement proper storage layout validation")
        
        if 'call_with_value' in pattern_names:
            recommendations.append("Implement reentrancy guards and checks-effects-interactions pattern")
        
        if 'origin_dependency' in pattern_names:
            recommendations.append("Avoid using tx.origin for authorization checks")
        
        if 'block_timestamp_dependency' in pattern_names:
            recommendations.append("Avoid using block.timestamp for randomness or critical logic")
        
        # Recomendaciones basadas en control flow
        if control_flow['jump_density'] > 0.1:
            recommendations.append("High jump density detected - Consider simplifying control flow")
        
        if control_flow['call_density'] > 0.2:
            recommendations.append("High call density detected - Consider batching external calls")
        
        # Recomendaciones basadas en gas
        if gas_analysis['gas_efficiency'] < 0.5:
            recommendations.append("Low gas efficiency detected - Optimize expensive operations")
        
        if len(gas_analysis['expensive_operations']) > 5:
            recommendations.append("Many expensive operations detected - Consider gas optimization strategies")
        
        return recommendations

# Demo
def demo_bytecode_analysis():
    """Demostración del analizador de bytecode"""
    analyzer = BytecodeAnalyzer()
    
    # Bytecode de ejemplo (contrato simple)
    example_bytecode = "0x608060405234801561001057600080fd5b50600436106100365760003560e01c8063c2985578146100405780638da5cb5b14610056575b600080fd5b61005e60048036038101908080359060200190929190505050610082565b6040518080602001828103825283818151815260200191508051906020019082938201902091905261007d91610082565b005b600080fd5b60008090505080505056"
    
    print("Analyzing bytecode...")
    result = analyzer.analyze_bytecode(example_bytecode)
    
    print(f"Analysis Results:")
    print(f"Bytecode length: {result['bytecode_length']}")
    print(f"Instructions count: {result['instructions_count']}")
    print(f"Risk level: {result['risk_level']}")
    print(f"Risk score: {result['overall_risk_score']:.2%}")
    
    print(f"\nPatterns found: {len(result['patterns'])}")
    for pattern in result['patterns']:
        print(f"- {pattern.name} ({pattern.severity}): {pattern.description}")
    
    print(f"\nControl Flow:")
    print(f"- Jump density: {result['control_flow']['jump_density']:.2%}")
    print(f"- Call density: {result['control_flow']['call_density']:.2%}")
    print(f"- Complexity score: {result['control_flow']['complexity_score']:.2%}")
    
    print(f"\nGas Analysis:")
    print(f"- Total gas: {result['gas_analysis']['total_gas']}")
    print(f"- Gas efficiency: {result['gas_analysis']['gas_efficiency']:.2%}")
    print(f"- Expensive operations: {len(result['gas_analysis']['expensive_operations'])}")
    
    print(f"\nRecommendations:")
    for rec in result['recommendations']:
        print(f"- {rec}")

if __name__ == "__main__":
    demo_bytecode_analysis()
