"""
Security configuration management for MCP

This module handles the configuration of security policies and settings
for the Adaptive Security Mesh.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass
from pathlib import Path
import yaml
from . import SecurityLevel, SecurityPolicy

@dataclass
class SecurityConfig:
    """Security configuration container"""
    policy_file: Path
    threat_intelligence_sources: List[str]
    credential_stores: List[str]
    protocol_registry: Dict[str, Dict]

    @classmethod
    def from_yaml(cls, config_path: Path) -> 'SecurityConfig':
        """Load configuration from YAML file"""
        with open(config_path) as f:
            config_data = yaml.safe_load(f)
        
        return cls(
            policy_file=Path(config_data['policy_file']),
            threat_intelligence_sources=config_data['threat_intelligence_sources'],
            credential_stores=config_data['credential_stores'],
            protocol_registry=config_data['protocol_registry']
        )

def load_security_policy(config: SecurityConfig) -> SecurityPolicy:
    """Load security policy from configuration"""
    with open(config.policy_file) as f:
        policy_data = yaml.safe_load(f)
    
    return SecurityPolicy(
        default_level=SecurityLevel[policy_data['default_level']],
        sensitivity_thresholds=policy_data['sensitivity_thresholds'],
        protocol_mappings={
            SecurityLevel[level]: protocol 
            for level, protocol in policy_data['protocol_mappings'].items()
        },
        credential_requirements={
            SecurityLevel[level]: requirements 
            for level, requirements in policy_data['credential_requirements'].items()
        },
        threat_intelligence_sources=config.threat_intelligence_sources
    )

def save_security_policy(policy: SecurityPolicy, config: SecurityConfig) -> None:
    """Save security policy to configuration file"""
    policy_data = {
        'default_level': policy.default_level.name,
        'sensitivity_thresholds': policy.sensitivity_thresholds,
        'protocol_mappings': {
            level.name: protocol 
            for level, protocol in policy.protocol_mappings.items()
        },
        'credential_requirements': {
            level.name: requirements 
            for level, requirements in policy.credential_requirements.items()
        }
    }
    
    with open(config.policy_file, 'w') as f:
        yaml.safe_dump(policy_data, f) 