import asyncio
from pathlib import Path
from agents.mcp.server import MCPServerStdio, MCPServerStdioParams
from agents.mcp.security import SecurityMesh, SecurityConfig, SecurityLevel, AccessLevel

async def main():
    # Create security configuration
    config = SecurityConfig(
        policy_file=Path("examples/security/config.yaml"),
        threat_intelligence_sources=["test_source"],
        credential_stores=["test_store"],
        protocol_registry={
            "tls_1_3": {"name": "TLS 1.3", "min_strength": 256},
            "aes_256": {"name": "AES-256", "mode": "GCM", "key_length": 256}
        }
    )

    # Create security mesh
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
        "protocols": config.protocol_registry
    }
    security_mesh = SecurityMesh(policy)

    # Create MCP server parameters
    server_params = MCPServerStdioParams(
        command="python",
        args=["examples/security/test_server.py"],
        cwd=str(Path.cwd())
    )

    # Create and connect to MCP server
    server = MCPServerStdio(
        params=server_params,
        cache_tools_list=True,
        name="Test MCP Server"
    )

    try:
        # Connect to server
        await server.connect()
        print("Connected to MCP server")

        # List available tools
        tools = await server.list_tools()
        print("\nAvailable tools:")
        for tool in tools:
            print(f"- {tool.name}")

        # Test tool access validation
        user_context = {
            "access_level": AccessLevel.INTERNAL,
            "roles": ["admin"],
            "credentials": ["oauth2"]
        }
        
        # Process input data
        input_data = {
            "query": "SELECT * FROM users WHERE ssn='123-45-6789'",
            "data": "sensitive information"
        }
        
        processed_data = await security_mesh.process_input(input_data)
        print("\nProcessed input data:")
        print(processed_data)

        # Call a tool with processed data
        result = await server.call_tool("read_data", processed_data)
        print("\nTool call result:")
        print(result)

    except Exception as e:
        print(f"Error: {e}")
    finally:
        await server.cleanup()

if __name__ == "__main__":
    asyncio.run(main()) 