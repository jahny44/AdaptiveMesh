"""
Security mesh integration with MCP server

This module provides the integration layer between the Adaptive Security Mesh
and the MCP server components.
"""

from typing import Dict, Any, Optional, Union
from ..server import MCPRequest, MCPResponse
from . import SecurityMesh, SecurityPolicy
from .config import SecurityConfig, load_security_policy
from pathlib import Path

class SecurityMiddleware:
    """Middleware for integrating security mesh with MCP server"""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.policy = load_security_policy(config)
        self.security_mesh = SecurityMesh(self.policy)

    async def process_request(self, request: MCPRequest) -> Optional[MCPResponse]:
        """Process incoming request through security mesh"""
        # Evaluate security requirements
        security_level = await self.security_mesh.evaluate_security(request.data)
        
        # Apply security measures
        await self._apply_security_measures(request, security_level)
        
        return None  # Continue processing

    async def process_response(self, response: MCPResponse) -> MCPResponse:
        """Process outgoing response through security mesh"""
        # Evaluate security requirements
        security_level = await self.security_mesh.evaluate_security(response.data)
        
        # Apply security measures
        await self._apply_security_measures(response, security_level)
        
        return response

    async def _apply_security_measures(
        self, 
        message: Union[MCPRequest, MCPResponse], 
        security_level: SecurityLevel
    ) -> None:
        """Apply appropriate security measures based on security level"""
        # Select protocol
        protocol = await self.security_mesh.protocol_manager.select_protocol(security_level)
        
        # Get required credentials
        credentials = await self.security_mesh.credential_manager.get_credentials(security_level)
        
        # Apply protocol and credentials
        message.security_protocol = protocol
        message.credentials = credentials

def create_security_middleware(config_path: str) -> SecurityMiddleware:
    """Factory function to create security middleware"""
    config = SecurityConfig.from_yaml(Path(config_path))
    return SecurityMiddleware(config) 