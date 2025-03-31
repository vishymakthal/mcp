package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/vishymakthal/mcp"
)

// fetchEndpointTool is a simple tool that fetches data from an endpoint
// This is a placeholder implementation - the actual functionality should be filled in later
func fetchEndpointTool(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to fetch from endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("received non-200 status code: %d", resp.StatusCode)
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	// Check the Content-Type to determine how to handle the response
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		// For JSON content, pretty print it
		var jsonObj interface{}
		if err := json.Unmarshal(body, &jsonObj); err != nil {
			// If unmarshaling fails, just return the raw body as string
			return string(body), nil
		}

		// Pretty print the JSON
		prettyJSON, err := json.MarshalIndent(jsonObj, "", "  ")
		if err != nil {
			// If pretty printing fails, return the raw body
			return string(body), nil
		}
		return string(prettyJSON), nil
	}

	// For all other content types, return as plain text
	return string(body), nil
}

func main() {
	// Create server info
	serverInfo := mcp.Implementation{
		Name:    "Simple MCP Server",
		Version: "1.0.0",
	}

	// Define server capabilities
	capabilities := mcp.ServerCapabilities{
		Tools: &struct {
			ListChanged bool `json:"listChanged,omitempty"`
		}{
			ListChanged: true,
		},
	}

	// Create the MCP server
	server := mcp.NewServer(serverInfo, capabilities)

	// Define the fetch endpoint tool
	fetchTool := mcp.Tool{
		Name:        "get-ip",
		Description: "Fetches current IP address from specified URL",
		InputSchema: struct {
			Type       string                     `json:"type"`
			Properties map[string]json.RawMessage `json:"properties,omitempty"`
			Required   []string                   `json:"required,omitempty"`
		}{
			Type: "object",
			Properties: map[string]json.RawMessage{
				"url": []byte(`{
					"type": "string",
					"description": "The URL of the endpoint to fetch data from"
				}`),
			},
			Required: []string{"url"},
		},
	}

	// Add the tool to the server
	server.AddTool(fetchTool)

	// Register the tool handler
	err := server.RegisterToolHandler("get-ip", func(arguments map[string]interface{}) (string, error) {
		// Extract URL from arguments
		urlArg, ok := arguments["url"]
		if !ok {
			return "", fmt.Errorf("missing required argument: url")
		}

		url, ok := urlArg.(string)
		if !ok {
			return "", fmt.Errorf("url must be a string")
		}

		// Call the actual tool function
		return fetchEndpointTool(url)
	})

	if err != nil {
		log.Fatalf("Error registering tool handler: %v", err)
	}

	// Set up a signal handler for graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Create an HTTP server to handle MCP requests
	httpServer := &http.Server{
		Addr: ":3000",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only accept POST requests to /jsonrpc endpoint
			if r.Method != http.MethodPost || r.URL.Path != "/jsonrpc" {
				http.Error(w, "Method or path not allowed", http.StatusMethodNotAllowed)
				return
			}

			// Read the request body
			requestBytes := make([]byte, r.ContentLength)
			_, err := r.Body.Read(requestBytes)
			if err != nil && err.Error() != "EOF" {
				http.Error(w, "Error reading request body", http.StatusBadRequest)
				return
			}

			// Pass the request to the MCP server handler
			responseBytes, err := server.Handle(requestBytes)
			if err != nil {
				if responseBytes == nil {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			if responseBytes == nil {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.Write(responseBytes)
		}),
	}

	// Start the server in a goroutine
	go func() {
		log.Printf("Starting MCP server on %s...", httpServer.Addr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Error starting server: %v", err)
		}
	}()

	// Wait for interrupt signal
	<-stop
	log.Println("Shutting down server...")

	// Stop the server
	if err := httpServer.Close(); err != nil {
		log.Fatalf("Error stopping server: %v", err)
	}

	log.Println("Server stopped")
}
