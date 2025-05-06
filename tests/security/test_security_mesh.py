"""
Tests for the Adaptive Security Mesh implementation.
"""

import pytest
from pathlib import Path
from agents.mcp.security.types import SecurityLevel, AccessLevel, SecurityConfig
from agents.mcp.security.mesh import SecurityMesh
from agents.mcp.security.integration import SecurityMiddleware
from agents.mcp.server import MCPRequest, MCPResponse

@pytest.fixture
def security_config():
    """Create test security configuration"""
    return SecurityConfig(
        policy_file=Path("tests/security/test_policy.yaml"),
        threat_intelligence_sources=["test_source"],
        protocols={
            "tls_1_3": {"name": "TLS 1.3", "min_strength": 256},
            "aes_256": {"name": "AES-256", "mode": "GCM", "key_length": 256}
        }
    )

@pytest.fixture
def security_mesh(security_config):
    """Create test security mesh instance"""
    policy = {
        "tools": {
            "read_data": {
                "required_level": AccessLevel.INTERNAL,
                "required_roles": ["admin", "reader"],
                "required_credentials": ["oauth2"],
                "input_sensitivity": SecurityLevel.MEDIUM,
                "output_sensitivity": SecurityLevel.MEDIUM
            }
        },
        "protocols": security_config.protocols
    }
    return SecurityMesh(policy)

@pytest.mark.asyncio
async def test_security_mesh_initialization(security_mesh):
    """Test security mesh initialization"""
    assert security_mesh.policy is not None
    assert security_mesh.protocol_manager is not None
    assert security_mesh.credential_manager is not None

@pytest.mark.asyncio
async def test_tool_access_validation(security_mesh):
    """Test tool access validation"""
    # Test valid access
    user_context = {
        "access_level": AccessLevel.INTERNAL,
        "roles": ["admin"],
        "credentials": ["oauth2", "api_key"]
    }
    assert await security_mesh.security_features.validate_tool_access("read_data", user_context)

    # Test invalid access level
    user_context["access_level"] = AccessLevel.PUBLIC
    assert not await security_mesh.security_features.validate_tool_access("read_data", user_context)

@pytest.mark.asyncio
async def test_input_processing(security_mesh):
    """Test input processing and security measures"""
    input_data = {
        "query": "SELECT * FROM users WHERE ssn='123-45-6789'",
        "data": "sensitive information"
    }

    processed_data = await security_mesh.process_input(input_data)

    # Verify sensitive data is masked
    assert "123-45-6789" not in processed_data["query"]
    assert "[MASKED_SSN]" in processed_data["query"]

@pytest.mark.asyncio
async def test_output_processing(security_mesh):
    """Test output processing and security measures"""
    output_data = {
        "result": "User data: John Doe (SSN: 123-45-6789)",
        "metadata": "public information"
    }

    processed_output = await security_mesh.process_output(output_data)

    # Verify sensitive data is masked
    assert "123-45-6789" not in processed_output["result"]
    assert "[MASKED_SSN]" in processed_output["result"]

@pytest.mark.asyncio
async def test_protocol_selection(security_mesh):
    """Test protocol selection based on security level"""
    # Test LOW security level
    protocol = await security_mesh.protocol_manager.select_protocol(SecurityLevel.LOW)
    assert "tls_1_3" in protocol

    # Test MEDIUM security level
    protocol = await security_mesh.protocol_manager.select_protocol(SecurityLevel.MEDIUM)
    assert "tls_1_3" in protocol
    assert "aes_256" in protocol

@pytest.mark.asyncio
async def test_credential_management(security_mesh):
    """Test credential management"""
    # Test LOW security level credentials
    credentials = await security_mesh.credential_manager.get_credentials(SecurityLevel.LOW)
    assert "basic_auth" in credentials

    # Test MEDIUM security level credentials
    credentials = await security_mesh.credential_manager.get_credentials(SecurityLevel.MEDIUM)
    assert "oauth2" in credentials

@pytest.mark.asyncio
async def test_threat_intelligence(security_mesh):
    """Test threat intelligence integration"""
    # This is a placeholder for future threat intelligence tests
    pass

@pytest.mark.asyncio
async def test_security_middleware(security_config):
    """Test security middleware integration"""
    middleware = SecurityMiddleware(security_config)

    # Test request processing
    request = MCPRequest(
        data={"sensitive": "123-45-6789"},
        headers={"Authorization": "Bearer token"},
        method="POST",
        path="/api/data"
    )

    processed_request = await middleware.process_request(request)
    assert processed_request is None  # Middleware continues processing
    assert "[MASKED_SSN]" in str(request.data["sensitive"])

    # Test response processing
    response = MCPResponse(
        data={"result": "SSN: 123-45-6789"},
        status=200,
        headers={"Content-Type": "application/json"}
    )

    processed_response = await middleware.process_response(response)
    assert "[MASKED_SSN]" in str(processed_response.data["result"]) 