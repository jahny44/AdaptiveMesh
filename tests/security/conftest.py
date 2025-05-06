"""
Configuration for security tests
"""

import pytest
from pathlib import Path
from agents.mcp.security import (
    SecurityMesh,
    SecurityPolicy,
    SecurityLevel,
    SecurityConfig,
    AccessLevel
)

@pytest.fixture
def security_config():
    return SecurityConfig(
        policy_file=Path("tests/security/test_policy.yaml"),
        threat_intelligence_sources=["test_source"],
        credential_stores=["test_store"],
        protocol_registry={
            "tls_1_3": {"name": "TLS 1.3", "min_strength": 256},
            "aes_256": {"name": "AES-256", "mode": "GCM", "key_length": 256}
        }
    )

@pytest.fixture
def security_policy():
    return SecurityPolicy(
        default_level=SecurityLevel.MEDIUM,
        sensitivity_thresholds={
            "personal_data": 0.8,
            "financial_data": 0.9
        },
        protocol_mappings={
            SecurityLevel.LOW: ["tls_1_3"],
            SecurityLevel.MEDIUM: ["tls_1_3", "aes_256"]
        },
        credential_requirements={
            SecurityLevel.LOW: ["basic_auth"],
            SecurityLevel.MEDIUM: ["oauth2", "api_key"]
        },
        threat_intelligence_sources=["test_source"]
    )

@pytest.fixture
def security_mesh(security_policy):
    return SecurityMesh(security_policy) 