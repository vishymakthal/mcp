# Model Context Protocol (MCP) Implementation in Go

This repository contains a Go implementation of the [Model Context Protocol (MCP)](https://github.com/microsoft/model-context-protocol), a JSON-RPC based protocol for interaction between clients and servers in LLM-powered applications.

## Contents

- `mcp/schema.go`: Go struct definitions for the MCP schema, translated from the TypeScript schema
- `mcp/client.go`: A client implementation for interacting with MCP servers
- `examples/mcp_client_example.go`: A simple example showing how to use the client

## MCP Overview

The Model Context Protocol (MCP) enables communication between model "hosts" (e.g., LLM clients or systems that interface with LLMs) and "servers" (systems that provide contextual information, tools, prompts, or resources to enhance LLM capabilities).

Key features of MCP include:
- **Resources**: Files, documents, and other data that a host can read
- **Tools**: Functions that a host can call on behalf of a model
- **Prompts**: Templates or pre-defined message sequences a host can use
- **Roots**: Filesystem or data roots that a server can operate on

## Getting Started

### Prerequisites

- Go 1.18 or later

### Running the Example

```bash
# Set the MCP server URL (optional, defaults to http://localhost:3000/jsonrpc)
export MCP_SERVER_URL=http://your-mcp-server/jsonrpc

# Run the example
go run examples/mcp_client_example.go
```

## Using the MCP Client

```go
import (
    "fmt"
    
    "path/to/mcp"
)

func main() {
    // Create a new client
    client := mcp.NewClient("http://your-mcp-server/jsonrpc")
    
    // Initialize the client
    clientInfo := mcp.Implementation{
        Name:    "My MCP Client",
        Version: "1.0.0",
    }
    
    capabilities := mcp.ClientCapabilities{
        // Specify the capabilities your client supports
    }
    
    err := client.Initialize(clientInfo, capabilities)
    if err != nil {
        // Handle error
    }
    
    // Now you can use various client methods:
    
    // List resources
    resources, err := client.ListResources("")
    
    // Read a resource
    resource, err := client.ReadResource("resource-uri")
    
    // Call a tool
    result, err := client.CallTool("tool-name", map[string]interface{}{
        "argument1": "value1",
        "argument2": 123,
    })
    
    // Get a prompt
    prompt, err := client.GetPrompt("prompt-name", map[string]string{
        "argName": "argValue",
    })
}
```

## Implementation Details

### Schema

The Go schema definitions in `mcp/schema.go` provide type-safe structures for MCP messages. This includes:

- JSON-RPC protocol structures
- Resource, Prompt, and Tool definitions
- Content structures for text, images, and embedded resources
- Helper functions for handling polymorphic types via `json.RawMessage`

### Client

The client implementation in `mcp/client.go` provides methods for:

- Initializing connections to MCP servers
- Sending requests and handling responses
- Converting Go structs to JSON-RPC messages
- Helper methods for common MCP operations

## Contributing

Contributions are welcome! Here are some ways you can contribute:

- Implement a server
- Add WebSocket support to the client
- Improve error handling
- Add tests
- Document additional use cases

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## References

- [Model Context Protocol Specification](https://github.com/microsoft/model-context-protocol/blob/main/schema.ts)
- [MCP GitHub Repository](https://github.com/microsoft/model-context-protocol) 