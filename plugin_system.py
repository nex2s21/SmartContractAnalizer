#!/usr/bin/env python3
"""
Plugin System and Extensibility Framework
Sistema de plugins para extender el analizador
"""

import os
import sys
import json
import importlib
import inspect
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from abc import ABC, abstractmethod
from pathlib import Path
import hashlib
import threading
import time
from datetime import datetime

@dataclass
class PluginMetadata:
    """Metadatos de un plugin"""
    name: str
    version: str
    description: str
    author: str
    email: str
    license: str
    homepage: str
    tags: List[str]
    dependencies: List[str]
    min_analyzer_version: str
    max_analyzer_version: str
    entry_point: str
    enabled: bool = True
    installed_at: Optional[datetime] = None
    last_updated: Optional[datetime] = None

@dataclass
class PluginCapability:
    """Capacidad de un plugin"""
    name: str
    description: str
    type: str  # 'analyzer', 'reporter', 'validator', 'transformer'
    input_types: List[str]
    output_types: List[str]
    parameters: Dict[str, Any]

class PluginInterface(ABC):
    """Interfaz base para todos los plugins"""
    
    @abstractmethod
    def get_metadata(self) -> PluginMetadata:
        """Obtiene metadatos del plugin"""
        pass
    
    @abstractmethod
    def get_capabilities(self) -> List[PluginCapability]:
        """Obtiene capacidades del plugin"""
        pass
    
    @abstractmethod
    def initialize(self, config: Dict[str, Any]) -> bool:
        """Inicializa el plugin con configuración"""
        pass
    
    @abstractmethod
    def execute(self, capability: str, data: Any, parameters: Dict[str, Any]) -> Any:
        """Ejecuta una capacidad del plugin"""
        pass
    
    @abstractmethod
    def cleanup(self) -> bool:
        """Limpia recursos del plugin"""
        pass

class AnalyzerPlugin(PluginInterface):
    """Plugin base para analizadores personalizados"""
    
    @abstractmethod
    def analyze(self, code: str, options: Dict[str, Any]) -> List[Dict]:
        """Analiza código y retorna hallazgos"""
        pass

class ReporterPlugin(PluginInterface):
    """Plugin base para reporteros personalizados"""
    
    @abstractmethod
    def generate_report(self, analysis_results: Dict[str, Any], output_path: str) -> str:
        """Genera reporte y retorna ruta del archivo"""
        pass

class ValidatorPlugin(PluginInterface):
    """Plugin base para validadores personalizados"""
    
    @abstractmethod
    def validate(self, data: Any, rules: Dict[str, Any]) -> Dict[str, Any]:
        """Valida datos según reglas"""
        pass

class TransformerPlugin(PluginInterface):
    """Plugin base para transformadores de datos"""
    
    @abstractmethod
    def transform(self, data: Any, transformation: str) -> Any:
        """Transforma datos"""
        pass

class PluginManager:
    """Gestor de plugins"""
    
    def __init__(self, plugin_dir: str = None):
        self.plugin_dir = Path(plugin_dir) if plugin_dir else Path(__file__).parent / "plugins"
        self.plugin_dir.mkdir(exist_ok=True)
        
        self.plugins: Dict[str, PluginInterface] = {}
        self.plugin_metadata: Dict[str, PluginMetadata] = {}
        self.plugin_capabilities: Dict[str, List[PluginCapability]] = {}
        
        self.registry_file = self.plugin_dir / "registry.json"
        self.load_registry()
        
        self._lock = threading.Lock()
    
    def load_registry(self):
        """Carga registro de plugins"""
        if self.registry_file.exists():
            try:
                with open(self.registry_file, 'r', encoding='utf-8') as f:
                    registry_data = json.load(f)
                
                for plugin_id, metadata in registry_data.items():
                    metadata['installed_at'] = datetime.fromisoformat(metadata['installed_at']) if metadata.get('installed_at') else None
                    metadata['last_updated'] = datetime.fromisoformat(metadata['last_updated']) if metadata.get('last_updated') else None
                    self.plugin_metadata[plugin_id] = PluginMetadata(**metadata)
            except Exception as e:
                print(f"Error loading plugin registry: {e}")
    
    def save_registry(self):
        """Guarda registro de plugins"""
        registry_data = {}
        for plugin_id, metadata in self.plugin_metadata.items():
            metadata_dict = asdict(metadata)
            metadata_dict['installed_at'] = metadata.installed_at.isoformat() if metadata.installed_at else None
            metadata_dict['last_updated'] = metadata.last_updated.isoformat() if metadata.last_updated else None
            registry_data[plugin_id] = metadata_dict
        
        with open(self.registry_file, 'w', encoding='utf-8') as f:
            json.dump(registry_data, f, indent=2, ensure_ascii=False)
    
    def discover_plugins(self) -> List[str]:
        """Descubre plugins en el directorio"""
        plugin_files = []
        
        for plugin_file in self.plugin_dir.glob("*.py"):
            if plugin_file.name.startswith("plugin_"):
                plugin_files.append(str(plugin_file))
        
        return plugin_files
    
    def install_plugin(self, plugin_path: str) -> bool:
        """Instala un plugin"""
        try:
            plugin_path = Path(plugin_path)
            
            if not plugin_path.exists():
                return False
            
            # Copiar plugin al directorio
            dest_path = self.plugin_dir / f"plugin_{plugin_path.stem}.py"
            
            with open(plugin_path, 'r', encoding='utf-8') as src:
                content = src.read()
            
            with open(dest_path, 'w', encoding='utf-8') as dst:
                dst.write(content)
            
            # Cargar y validar plugin
            if self.load_plugin(dest_path):
                print(f"Plugin installed successfully: {dest_path}")
                return True
            
            return False
            
        except Exception as e:
            print(f"Error installing plugin: {e}")
            return False
    
    def load_plugin(self, plugin_path: str) -> bool:
        """Carga un plugin"""
        try:
            with self._lock:
                # Importar módulo del plugin
                spec = importlib.util.spec_from_file_location("plugin", plugin_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Encontrar clases que implementan PluginInterface
                plugin_classes = []
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if issubclass(obj, PluginInterface) and obj != PluginInterface:
                        plugin_classes.append(obj)
                
                if not plugin_classes:
                    print(f"No plugin classes found in {plugin_path}")
                    return False
                
                # Instanciar plugin
                plugin_class = plugin_classes[0]
                plugin_instance = plugin_class()
                
                # Validar interfaz
                if not isinstance(plugin_instance, PluginInterface):
                    print(f"Plugin does not implement PluginInterface: {plugin_path}")
                    return False
                
                # Obtener metadatos
                metadata = plugin_instance.get_metadata()
                plugin_id = self._generate_plugin_id(metadata.name, metadata.version)
                
                # Guardar plugin
                self.plugins[plugin_id] = plugin_instance
                self.plugin_metadata[plugin_id] = metadata
                self.plugin_capabilities[plugin_id] = plugin_instance.get_capabilities()
                
                # Actualizar registro
                metadata.installed_at = datetime.now()
                metadata.last_updated = datetime.now()
                self.save_registry()
                
                print(f"Plugin loaded: {metadata.name} v{metadata.version}")
                return True
                
        except Exception as e:
            print(f"Error loading plugin {plugin_path}: {e}")
            return False
    
    def _generate_plugin_id(self, name: str, version: str) -> str:
        """Genera ID único para plugin"""
        content = f"{name}:{version}"
        return hashlib.md5(content.encode()).hexdigest()[:16]
    
    def uninstall_plugin(self, plugin_id: str) -> bool:
        """Desinstala un plugin"""
        try:
            with self._lock:
                if plugin_id not in self.plugins:
                    return False
                
                # Limpiar plugin
                self.plugins[plugin_id].cleanup()
                
                # Eliminar del registro
                del self.plugins[plugin_id]
                del self.plugin_metadata[plugin_id]
                del self.plugin_capabilities[plugin_id]
                
                # Guardar registro
                self.save_registry()
                
                print(f"Plugin uninstalled: {plugin_id}")
                return True
                
        except Exception as e:
            print(f"Error uninstalling plugin: {e}")
            return False
    
    def enable_plugin(self, plugin_id: str) -> bool:
        """Habilita un plugin"""
        if plugin_id in self.plugin_metadata:
            self.plugin_metadata[plugin_id].enabled = True
            self.save_registry()
            return True
        return False
    
    def disable_plugin(self, plugin_id: str) -> bool:
        """Deshabilita un plugin"""
        if plugin_id in self.plugin_metadata:
            self.plugin_metadata[plugin_id].enabled = False
            self.save_registry()
            return True
        return False
    
    def get_plugins_by_type(self, plugin_type: str) -> Dict[str, PluginInterface]:
        """Obtiene plugins por tipo"""
        result = {}
        
        for plugin_id, capabilities in self.plugin_capabilities.items():
            if plugin_id in self.plugins and self.plugin_metadata[plugin_id].enabled:
                for capability in capabilities:
                    if capability.type == plugin_type:
                        result[plugin_id] = self.plugins[plugin_id]
                        break
        
        return result
    
    def execute_plugin_capability(self, plugin_id: str, capability: str, data: Any, parameters: Dict[str, Any] = None) -> Any:
        """Ejecuta capacidad de un plugin"""
        if plugin_id not in self.plugins:
            raise ValueError(f"Plugin not found: {plugin_id}")
        
        if not self.plugin_metadata[plugin_id].enabled:
            raise ValueError(f"Plugin disabled: {plugin_id}")
        
        plugin = self.plugins[plugin_id]
        return plugin.execute(capability, data, parameters or {})
    
    def list_plugins(self) -> Dict[str, PluginMetadata]:
        """Lista todos los plugins"""
        return self.plugin_metadata.copy()
    
    def get_plugin_info(self, plugin_id: str) -> Optional[Dict[str, Any]]:
        """Obtiene información detallada de un plugin"""
        if plugin_id not in self.plugins:
            return None
        
        metadata = self.plugin_metadata[plugin_id]
        capabilities = self.plugin_capabilities.get(plugin_id, [])
        
        return {
            'metadata': asdict(metadata),
            'capabilities': [asdict(cap) for cap in capabilities],
            'loaded': True,
            'enabled': metadata.enabled
        }
    
    def initialize_all_plugins(self, config: Dict[str, Any] = None) -> Dict[str, bool]:
        """Inicializa todos los plugins"""
        results = {}
        
        for plugin_id, plugin in self.plugins.items():
            if self.plugin_metadata[plugin_id].enabled:
                try:
                    success = plugin.initialize(config or {})
                    results[plugin_id] = success
                    
                    if not success:
                        print(f"Failed to initialize plugin: {plugin_id}")
                        
                except Exception as e:
                    print(f"Error initializing plugin {plugin_id}: {e}")
                    results[plugin_id] = False
        
        return results
    
    def cleanup_all_plugins(self) -> Dict[str, bool]:
        """Limpia todos los plugins"""
        results = {}
        
        for plugin_id, plugin in self.plugins.items():
            try:
                success = plugin.cleanup()
                results[plugin_id] = success
            except Exception as e:
                print(f"Error cleaning up plugin {plugin_id}: {e}")
                results[plugin_id] = False
        
        return results

class PluginSDK:
    """SDK para desarrollo de plugins"""
    
    @staticmethod
    def create_plugin_template(plugin_name: str, plugin_type: str, output_dir: str = None):
        """Crea plantilla para nuevo plugin"""
        
        templates = {
            'analyzer': '''# Plugin Template - Analyzer
from plugin_system import AnalyzerPlugin, PluginMetadata, PluginCapability

class CustomAnalyzer(AnalyzerPlugin):
    """Custom analyzer plugin"""
    
    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="{plugin_name}",
            version="1.0.0",
            description="Custom analyzer for smart contracts",
            author="Your Name",
            email="your.email@example.com",
            license="MIT",
            homepage="https://github.com/yourusername/{plugin_name}",
            tags=["analyzer", "security", "smart-contracts"],
            dependencies=[],
            min_analyzer_version="1.0.0",
            max_analyzer_version="2.0.0",
            entry_point="CustomAnalyzer"
        )
    
    def get_capabilities(self) -> List[PluginCapability]:
        return [
            PluginCapability(
                name="custom_analysis",
                description="Performs custom security analysis",
                type="analyzer",
                input_types=["solidity_code"],
                output_types=["findings"],
                parameters={{"name": "strict_mode", "type": "boolean", "default": False}}
            )
        ]
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize plugin with configuration"""
        self.config = config
        return True
    
    def execute(self, capability: str, data: Any, parameters: Dict[str, Any]) -> Any:
        """Execute plugin capability"""
        if capability == "custom_analysis":
            return self.analyze(data, parameters)
        else:
            raise ValueError(f"Unknown capability: {{capability}}")
    
    def analyze(self, code: str, options: Dict[str, Any]) -> List[Dict]:
        """Custom analysis implementation"""
        findings = []
        
        # Your custom analysis logic here
        # Example: detect specific patterns
        
        return findings
    
    def cleanup(self) -> bool:
        """Cleanup plugin resources"""
        return True
''',
            'reporter': '''# Plugin Template - Reporter
from plugin_system import ReporterPlugin, PluginMetadata, PluginCapability

class CustomReporter(ReporterPlugin):
    """Custom reporter plugin"""
    
    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="{plugin_name}",
            version="1.0.0",
            description="Custom reporter for analysis results",
            author="Your Name",
            email="your.email@example.com",
            license="MIT",
            homepage="https://github.com/yourusername/{plugin_name}",
            tags=["reporter", "export", "visualization"],
            dependencies=[],
            min_analyzer_version="1.0.0",
            max_analyzer_version="2.0.0",
            entry_point="CustomReporter"
        )
    
    def get_capabilities(self) -> List[PluginCapability]:
        return [
            PluginCapability(
                name="custom_report",
                description="Generates custom format reports",
                type="reporter",
                input_types=["analysis_results"],
                output_types=["report_file"],
                parameters={{"name": "format", "type": "string", "default": "json"}}
            )
        ]
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize plugin with configuration"""
        self.config = config
        return True
    
    def execute(self, capability: str, data: Any, parameters: Dict[str, Any]) -> Any:
        """Execute plugin capability"""
        if capability == "custom_report":
            return self.generate_report(data, parameters.get("output_path", "report.custom"))
        else:
            raise ValueError(f"Unknown capability: {{capability}}")
    
    def generate_report(self, analysis_results: Dict[str, Any], output_path: str) -> str:
        """Custom report generation implementation"""
        # Your custom report generation logic here
        
        return output_path
    
    def cleanup(self) -> bool:
        """Cleanup plugin resources"""
        return True
''',
            'validator': '''# Plugin Template - Validator
from plugin_system import ValidatorPlugin, PluginMetadata, PluginCapability

class CustomValidator(ValidatorPlugin):
    """Custom validator plugin"""
    
    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="{plugin_name}",
            version="1.0.0",
            description="Custom validator for smart contracts",
            author="Your Name",
            email="your.email@example.com",
            license="MIT",
            homepage="https://github.com/yourusername/{plugin_name}",
            tags=["validator", "compliance", "rules"],
            dependencies=[],
            min_analyzer_version="1.0.0",
            max_analyzer_version="2.0.0",
            entry_point="CustomValidator"
        )
    
    def get_capabilities(self) -> List[PluginCapability]:
        return [
            PluginCapability(
                name="custom_validation",
                description="Performs custom validation rules",
                type="validator",
                input_types=["contract_code", "findings"],
                output_types=["validation_result"],
                parameters={{"name": "strict_mode", "type": "boolean", "default": False}}
            )
        ]
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize plugin with configuration"""
        self.config = config
        return True
    
    def execute(self, capability: str, data: Any, parameters: Dict[str, Any]) -> Any:
        """Execute plugin capability"""
        if capability == "custom_validation":
            return self.validate(data, parameters)
        else:
            raise ValueError(f"Unknown capability: {{capability}}")
    
    def validate(self, data: Any, rules: Dict[str, Any]) -> Dict[str, Any]:
        """Custom validation implementation"""
        result = {
            "valid": True,
            "errors": [],
            "warnings": []
        }
        
        # Your custom validation logic here
        
        return result
    
    def cleanup(self) -> bool:
        """Cleanup plugin resources"""
        return True
'''
        }
        
        template = templates.get(plugin_type, templates['analyzer'])
        
        if output_dir is None:
            output_dir = Path.cwd()
        else:
            output_dir = Path(output_dir)
        
        output_dir.mkdir(exist_ok=True)
        plugin_file = output_dir / f"plugin_{plugin_name.lower().replace(' ', '_')}.py"
        
        with open(plugin_file, 'w', encoding='utf-8') as f:
            f.write(template)
        
        print(f"Plugin template created: {plugin_file}")
        return str(plugin_file)

# Demo
def demo_plugin_system():
    """Demostración del sistema de plugins"""
    print("=== Plugin System Demo ===")
    
    # Crear gestor de plugins
    plugin_manager = PluginManager()
    
    # Crear plugin de ejemplo
    template_path = PluginSDK.create_plugin_template("DemoAnalyzer", "analyzer")
    print(f"Created template: {template_path}")
    
    # Cargar plugins existentes
    plugin_files = plugin_manager.discover_plugins()
    print(f"Discovered plugins: {len(plugin_files)}")
    
    # Listar plugins
    plugins = plugin_manager.list_plugins()
    print(f"Loaded plugins: {len(plugins)}")
    
    for plugin_id, metadata in plugins.items():
        print(f"- {metadata.name} v{metadata.version} ({'Enabled' if metadata.enabled else 'Disabled'})")

if __name__ == "__main__":
    demo_plugin_system()
