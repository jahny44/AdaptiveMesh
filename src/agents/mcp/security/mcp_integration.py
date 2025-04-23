"""
MCP-specific security mesh integration

This module provides specialized integration points for the Adaptive Security Mesh
with the MCP server implementation.
"""

from typing import Dict, Any, Optional
from pathlib import Path
from ..server import MCPServer, MCPServerStdio, MCPServerSse
from . import SecurityMesh, SecurityPolicy
from .config import SecurityConfig, load_security_policy

class SecureMCPServer:
    """Wrapper class that adds security mesh to MCP server"""
    
    def __init__(self, server: MCPServer, config: SecurityConfig):
        self.server = server
        self.config = config
        self.policy = load_security_policy(config)
        self.security_mesh = SecurityMesh(self.policy)
        
    async def connect(self):
        """Secure version of connect with security validation"""
        # Validate server identity and security posture
        await self.security_mesh.validate_server_identity(self.server)
        await self.server.connect()
        
    async def list_tools(self) -> list[Any]:
        """Secure version of list_tools with access control"""
        tools = await self.server.list_tools()
        # Filter tools based on security policy
        return await self.security_mesh.filter_tools(tools)
        
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any] | None) -> Any:
        """Secure version of call_tool with security validation"""
        # Validate tool access
        await self.security_mesh.validate_tool_access(tool_name)
        
        # Process input arguments
        secured_arguments = await self.security_mesh.process_input(arguments)
        
        # Call tool with secured arguments
        result = await self.server.call_tool(tool_name, secured_arguments)
        
        # Process output
        return await self.security_mesh.process_output(result)
        
    async def cleanup(self):
        """Secure cleanup with audit logging"""
        await self.security_mesh.audit_cleanup(self.server)
        await self.server.cleanup()

def create_secure_stdio_server(
    params: Dict[str, Any],
    config_path: str,
    cache_tools_list: bool = False,
    name: Optional[str] = None
) -> SecureMCPServer:
    """Factory function to create a secure stdio server"""
    server = MCPServerStdio(params, cache_tools_list, name)
    config = SecurityConfig.from_yaml(Path(config_path))
    return SecureMCPServer(server, config)

def create_secure_sse_server(
    params: Dict[str, Any],
    config_path: str,
    cache_tools_list: bool = False,
    name: Optional[str] = None
) -> SecureMCPServer:
    """Factory function to create a secure SSE server"""
    server = MCPServerSse(params, cache_tools_list, name)
    config = SecurityConfig.from_yaml(Path(config_path))
    return SecureMCPServer(server, config) 