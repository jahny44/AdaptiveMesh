"""
Demo script for Adaptive Security Mesh
"""

import asyncio
import json
from pathlib import Path
from agents.mcp.security import (
    SecurityMesh,
    SecurityPolicy,
    SecurityLevel,
    SecurityConfig,
    AccessLevel
)

async def demo_security_mesh():
    # Load configuration
    config_path = Path("examples/security/config.yaml")
    config = SecurityConfig.from_yaml(config_path)
    
    # Create security mesh
    policy = SecurityPolicy(
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
    
    security_mesh = SecurityMesh(policy)
    
    # Demo 1: Tool Access Validation
    print("\n=== Demo 1: Tool Access Validation ===")
    user_context = {
        "access_level": AccessLevel.INTERNAL,
        "roles": ["admin"],
        "credentials": ["oauth2", "api_key"]
    }
    
    # Test access to different tools
    tools = ["read_data", "process_sensitive"]
    for tool in tools:
        has_access = await security_mesh.security_features.validate_tool_access(tool, user_context)
        print(f"Access to {tool}: {'Granted' if has_access else 'Denied'}")
    
    # Demo 2: Input Processing
    print("\n=== Demo 2: Input Processing ===")
    sensitive_input = {
        "query": "SELECT * FROM users WHERE ssn='123-45-6789'",
        "data": "sensitive information"
    }
    
    processed_input = await security_mesh.process_input(sensitive_input)
    print("Original input:", json.dumps(sensitive_input, indent=2))
    print("Processed input:", json.dumps(processed_input, indent=2))
    
    # Demo 3: Output Processing
    print("\n=== Demo 3: Output Processing ===")
    sensitive_output = {
        "result": "User data: John Doe (SSN: 123-45-6789)",
        "metadata": "public information"
    }
    
    processed_output = await security_mesh.process_output(sensitive_output)
    print("Original output:", json.dumps(sensitive_output, indent=2))
    print("Processed output:", json.dumps(processed_output, indent=2))
    
    # Demo 4: Protocol Selection
    print("\n=== Demo 4: Protocol Selection ===")
    for level in SecurityLevel:
        protocol = await security_mesh.protocol_manager.select_protocol(level)
        print(f"Security Level {level.name}: {protocol}")
    
    # Demo 5: Credential Management
    print("\n=== Demo 5: Credential Management ===")
    for level in SecurityLevel:
        credentials = await security_mesh.credential_manager.get_credentials(level)
        print(f"Security Level {level.name}: {credentials}")
    
    # Demo 6: Threat Intelligence
    print("\n=== Demo 6: Threat Intelligence ===")
    threat_level = await security_mesh.threat_intelligence.get_current_level()
    print(f"Current threat level: {threat_level}")

if __name__ == "__main__":
    asyncio.run(demo_security_mesh()) 