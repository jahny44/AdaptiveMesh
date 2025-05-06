"""
Security types and enums for the Adaptive Security Mesh.
"""

from enum import Enum, auto
from typing import Dict, List, Any
from dataclasses import dataclass
from pathlib import Path

class SecurityLevel(Enum):
    """Security level classifications"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __lt__(self, other):
        if not isinstance(other, SecurityLevel):
            return NotImplemented
        return self.value < other.value

class AccessLevel(Enum):
    """Access level classifications"""
    PUBLIC = 1
    INTERNAL = 2
    RESTRICTED = 3
    ADMIN = 4

    def __lt__(self, other):
        if not isinstance(other, AccessLevel):
            return NotImplemented
        return self.value < other.value

@dataclass
class SecurityPolicy:
    """Configuration for security mesh behavior"""
    default_level: SecurityLevel
    sensitivity_thresholds: Dict[str, float]
    protocol_mappings: Dict[SecurityLevel, List[str]]
    credential_requirements: Dict[SecurityLevel, List[str]]
    threat_intelligence_sources: List[str]

@dataclass
class SecurityConfig:
    """Security configuration"""
    policy_file: Path
    threat_intelligence_sources: List[str]
    protocols: Dict[str, Dict[str, Any]] 