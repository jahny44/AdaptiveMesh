"""
Example of using the Secure MCP Server with Adaptive Security Mesh
"""

import asyncio
from pathlib import Path
from agents.mcp.security.mcp_integration import create_secure_stdio_server

async def main():
    # Configuration paths
    config_path = Path("examples/security/config.yaml")
    
    # MCP server parameters
    server_params = {
        "command": "python",
        "args": ["my_mcp_server.py"],
        "env": {"PYTHONPATH": "."},
        "cwd": ".",
        "encoding": "utf-8"
    }
    
    # Create secure server
    server = create_secure_stdio_server(
        params=server_params,
        config_path=str(config_path),
        name="Secure MCP Server"
    )
    
    try:
        # Connect to server
        await server.connect()
        
        # List available tools (filtered by security policy)
        tools = await server.list_tools()
        print("Available tools:", tools)
        
        # Example tool call with security validation
        result = await server.call_tool(
            "example_tool",
            {"input": "sensitive data"}
        )
        print("Tool result:", result)
        
    finally:
        # Cleanup with audit logging
        await server.cleanup()

if __name__ == "__main__":
    asyncio.run(main()) 