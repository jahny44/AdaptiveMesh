"""
Security mesh integration with MCP server

This module provides the integration layer between the Adaptive Security Mesh
and the MCP server components.
"""

from typing import Dict, Any, Optional, Union
from ..server import MCPRequest, MCPResponse
from .types import SecurityLevel, SecurityConfig
from .mesh import SecurityMesh

def load_security_policy(config: SecurityConfig) -> dict:
    """Load security policy from configuration"""
    # For now, return a basic policy
    return {
        "tools": {
            "read_data": {
                "required_level": "INTERNAL",
                "required_roles": ["admin", "reader"],
                "required_credentials": ["oauth2"],
                "input_sensitivity": "MEDIUM",
                "output_sensitivity": "MEDIUM"
            }
        },
        "protocols": {
            "tls_1_3": {"name": "TLS 1.3", "min_strength": 256},
            "aes_256": {"name": "AES-256", "mode": "GCM", "key_length": 256}
        }
    }

class SecurityMiddleware:
    """Middleware for integrating security mesh with MCP server"""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.policy = load_security_policy(config)
        self.security_mesh = SecurityMesh(self.policy)

    async def process_request(self, request: MCPRequest) -> Optional[MCPResponse]:
        """Process incoming request through security mesh"""
        # Process input data
        secured_data = await self.security_mesh.process_input(request.data)
        request.data = secured_data
        
        return None  # Continue processing

    async def process_response(self, response: MCPResponse) -> MCPResponse:
        """Process outgoing response through security mesh"""
        # Process output data
        secured_data = await self.security_mesh.process_output(response.data)
        response.data = secured_data
        
        return response

def create_security_middleware(config_path: str) -> SecurityMiddleware:
    """Factory function to create security middleware"""
    config = SecurityConfig.from_yaml(Path(config_path))
    return SecurityMiddleware(config) 