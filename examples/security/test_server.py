import asyncio
import json
from typing import Dict, Any
from mcp import StdioServer, Tool

class TestServer(StdioServer):
    def __init__(self):
        super().__init__()
        self.tools = [
            Tool(
                name="read_data",
                description="Read data with security measures",
                parameters={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "data": {"type": "string"}
                    }
                }
            )
        ]

    async def handle_call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if tool_name == "read_data":
            # Simulate data processing
            query = arguments.get("query", "")
            data = arguments.get("data", "")
            
            # Return processed data
            return {
                "status": "success",
                "result": f"Processed query: {query}\nProcessed data: {data}"
            }
        
        raise ValueError(f"Unknown tool: {tool_name}")

async def main():
    server = TestServer()
    await server.serve()

if __name__ == "__main__":
    asyncio.run(main()) 