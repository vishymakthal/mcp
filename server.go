package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// Server defines the interface for an MCP server
type Server interface {
	// Handle processes incoming JSON-RPC requests and returns appropriate responses
	Handle(request []byte) ([]byte, error)

	// Start starts the HTTP server to listen for MCP requests
	Start(address string) error

	// Stop stops the HTTP server
	Stop() error
}

// AuthConfig defines authentication configuration for the MCP server
type AuthConfig struct {
	// Whether authentication is required
	Required bool
	// Username for basic auth
	Username string
	// Password for basic auth
	Password string
	// Custom validator function for more complex auth schemes
	Validator func(username, password string) bool
}

// DefaultServer is a basic implementation of an MCP server
type DefaultServer struct {
	// ServerInfo contains information about this server
	serverInfo Implementation

	// Capabilities describes what this server can do
	capabilities ServerCapabilities

	// RequestHandlers maps method names to handler functions
	requestHandlers map[string]RequestHandler

	// NotificationHandlers maps notification method names to handler functions
	notificationHandlers map[string]NotificationHandler

	// Authentication configuration
	authConfig *AuthConfig

	// HTTP server instance
	httpServer *http.Server

	// Resources available on this server
	resources      []Resource
	resourcesMutex sync.RWMutex

	// Prompts available on this server
	prompts      []Prompt
	promptsMutex sync.RWMutex

	// Tools available on this server
	tools        []Tool
	toolHandlers map[string]ToolHandler
	toolsMutex   sync.RWMutex

	// Initialized indicates if the server has been initialized
	initialized bool
	initMutex   sync.RWMutex
}

// RequestHandler defines a function that handles a JSON-RPC request
type RequestHandler func(id RequestID, params map[string]interface{}) (interface{}, error)

// NotificationHandler defines a function that handles a JSON-RPC notification
type NotificationHandler func(params map[string]interface{}) error

// ToolHandler defines a function that handles a tool call
type ToolHandler func(arguments map[string]interface{}) (string, error)

// NewServer creates a new MCP server with the given configuration
func NewServer(serverInfo Implementation, capabilities ServerCapabilities) *DefaultServer {
	server := &DefaultServer{
		serverInfo:           serverInfo,
		capabilities:         capabilities,
		requestHandlers:      make(map[string]RequestHandler),
		notificationHandlers: make(map[string]NotificationHandler),
		resources:            []Resource{},
		prompts:              []Prompt{},
		tools:                []Tool{},
		toolHandlers:         make(map[string]ToolHandler),
		authConfig:           nil, // No authentication by default
	}

	// Register built-in request handlers
	server.registerRequestHandlers()

	// Register built-in notification handlers
	server.registerNotificationHandlers()

	return server
}

// Helper function to check if protocol versions are compatible
func isProtocolVersionCompatible(clientVersion, serverVersion string) bool {
	// If versions are identical, they're compatible
	if clientVersion == serverVersion {
		return true
	}

	// Split versions into components (year-month-day)
	clientParts := strings.Split(clientVersion, "-")
	serverParts := strings.Split(serverVersion, "-")

	// Ensure both have valid format
	if len(clientParts) != 3 || len(serverParts) != 3 {
		// If format is invalid, require exact match
		return false
	}

	// Parse years
	clientYear, errClient := strconv.Atoi(clientParts[0])
	serverYear, errServer := strconv.Atoi(serverParts[0])
	if errClient != nil || errServer != nil {
		return false
	}

	// Different years - major version change
	if clientYear != serverYear {
		// Server can support older client versions, but client may not support newer server versions
		return clientYear < serverYear
	}

	// Same year, check month
	clientMonth, errClient := strconv.Atoi(clientParts[1])
	serverMonth, errServer := strconv.Atoi(serverParts[1])
	if errClient != nil || errServer != nil {
		return false
	}

	// Different months - minor version change
	if clientMonth != serverMonth {
		// Server can support older client versions, but client may not support newer server versions
		return clientMonth < serverMonth
	}

	// Same year and month, check day
	clientDay, errClient := strconv.Atoi(clientParts[2])
	serverDay, errServer := strconv.Atoi(serverParts[2])
	if errClient != nil || errServer != nil {
		return false
	}

	// Different days - patch version change, should be compatible
	// Server should be able to handle older client versions
	return clientDay <= serverDay
}

// registerRequestHandlers registers the built-in request handlers
func (s *DefaultServer) registerRequestHandlers() {
	// Initialize request
	s.requestHandlers["initialize"] = func(id RequestID, params map[string]interface{}) (interface{}, error) {
		s.initMutex.Lock()
		defer s.initMutex.Unlock()

		// Parse params
		paramsBytes, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("error marshaling params: %w", err)
		}

		var initParams struct {
			ProtocolVersion string             `json:"protocolVersion"`
			Capabilities    ClientCapabilities `json:"capabilities"`
			ClientInfo      Implementation     `json:"clientInfo"`
		}

		if err := json.Unmarshal(paramsBytes, &initParams); err != nil {
			return nil, fmt.Errorf("error unmarshaling initialize params: %w", err)
		}

		// Check protocol version compatibility
		if !isProtocolVersionCompatible(initParams.ProtocolVersion, LatestProtocolVersion) {
			fmt.Printf("Warning: Client requested protocol version %s, but server supports %s\n",
				initParams.ProtocolVersion, LatestProtocolVersion)
			fmt.Println("Protocol versions may be incompatible")
		}

		s.initialized = true

		// Return initialize result
		return InitializeResult{
			ProtocolVersion: LatestProtocolVersion,
			Capabilities:    s.capabilities,
			ServerInfo:      s.serverInfo,
		}, nil
	}

	// Ping request
	s.requestHandlers["ping"] = func(id RequestID, params map[string]interface{}) (interface{}, error) {
		// Just return an empty result
		return EmptyResult{}, nil
	}

	// List resources request
	s.requestHandlers["resources/list"] = func(id RequestID, params map[string]interface{}) (interface{}, error) {
		if !s.isInitialized() {
			return nil, errors.New("server not initialized")
		}

		// Parse pagination parameters
		var cursor Cursor
		var pageSize int = 20 // Default page size

		// Extract cursor if provided
		if cursorVal, ok := params["cursor"]; ok {
			if cursorStr, ok := cursorVal.(string); ok {
				cursor = Cursor(cursorStr)
			}
		}

		// Extract page size if provided (optional extension)
		if pageSizeVal, ok := params["pageSize"]; ok {
			if pageSizeInt, ok := pageSizeVal.(float64); ok {
				pageSize = int(pageSizeInt)
				if pageSize < 1 {
					pageSize = 20 // Enforce reasonable defaults
				} else if pageSize > 100 {
					pageSize = 100 // Cap at 100 items per page
				}
			}
		}

		s.resourcesMutex.RLock()
		defer s.resourcesMutex.RUnlock()

		// Implement pagination logic
		var startIndex int = 0
		if cursor != "" {
			// Try to parse the cursor as an index
			if idx, err := strconv.Atoi(string(cursor)); err == nil && idx >= 0 && idx < len(s.resources) {
				startIndex = idx
			}
		}

		// Calculate end index for pagination
		endIndex := startIndex + pageSize
		if endIndex > len(s.resources) {
			endIndex = len(s.resources)
		}

		// Get the page of resources
		var pagedResources []Resource
		if startIndex < len(s.resources) {
			pagedResources = s.resources[startIndex:endIndex]
		} else {
			pagedResources = []Resource{}
		}

		// Create the result
		result := ListResourcesResult{
			Resources: pagedResources,
		}

		// Set next cursor if there are more items
		if endIndex < len(s.resources) {
			result.NextCursor = Cursor(strconv.Itoa(endIndex))
		}

		return result, nil
	}

	// List prompts request
	s.requestHandlers["prompts/list"] = func(id RequestID, params map[string]interface{}) (interface{}, error) {
		if !s.isInitialized() {
			return nil, errors.New("server not initialized")
		}

		// For simplicity, we're ignoring any cursor in this implementation

		s.promptsMutex.RLock()
		prompts := s.prompts
		s.promptsMutex.RUnlock()

		return ListPromptsResult{
			Prompts: prompts,
		}, nil
	}

	// List tools request
	s.requestHandlers["tools/list"] = func(id RequestID, params map[string]interface{}) (interface{}, error) {
		if !s.isInitialized() {
			return nil, errors.New("server not initialized")
		}

		// For simplicity, we're ignoring any cursor in this implementation

		s.toolsMutex.RLock()
		tools := s.tools
		s.toolsMutex.RUnlock()

		return ListToolsResult{
			Tools: tools,
		}, nil
	}

	// Tools call request
	s.requestHandlers["tools/call"] = func(id RequestID, params map[string]interface{}) (interface{}, error) {
		if !s.isInitialized() {
			return nil, errors.New("server not initialized")
		}

		// Parse the tool call parameters
		paramsBytes, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("error marshaling tool call params: %w", err)
		}

		var callParams struct {
			Name      string                 `json:"name"`
			Arguments map[string]interface{} `json:"arguments,omitempty"`
		}

		if err := json.Unmarshal(paramsBytes, &callParams); err != nil {
			return nil, fmt.Errorf("error unmarshaling tool call params: %w", err)
		}

		// Find the requested tool
		s.toolsMutex.RLock()
		var requestedTool *Tool
		for _, tool := range s.tools {
			if tool.Name == callParams.Name {
				requestedTool = &tool
				break
			}
		}

		// Check if we have a handler for this tool
		handler, handlerExists := s.toolHandlers[callParams.Name]
		s.toolsMutex.RUnlock()

		if requestedTool == nil {
			return nil, fmt.Errorf("tool not found: %s", callParams.Name)
		}

		var resultText string
		var resultErr error

		if handlerExists {
			// Call the custom handler if one exists
			resultText, resultErr = handler(callParams.Arguments)
		} else {
			// No handler, return a placeholder message
			resultText = fmt.Sprintf("Tool '%s' called with arguments: %v. No implementation provided.",
				callParams.Name, callParams.Arguments)
		}

		// Check if there was an error from the handler
		isError := resultErr != nil
		if isError && resultText == "" {
			resultText = resultErr.Error()
		}

		// Create a text content response
		textContent := TextContent{
			Type: ContentTypeText,
			Text: resultText,
		}

		// Marshal the content
		contentBytes, err := json.Marshal(textContent)
		if err != nil {
			return nil, fmt.Errorf("error marshaling content: %w", err)
		}

		// Return the result
		return CallToolResult{
			Content: []json.RawMessage{contentBytes},
			IsError: isError,
		}, nil
	}
}

// registerNotificationHandlers registers the built-in notification handlers
func (s *DefaultServer) registerNotificationHandlers() {
	// Initialized notification
	s.notificationHandlers["notifications/initialized"] = func(params map[string]interface{}) error {
		// This notification is simply acknowledging that initialization is complete
		// No action needed in this simple implementation
		return nil
	}
}

// isInitialized checks if the server has been initialized
func (s *DefaultServer) isInitialized() bool {
	s.initMutex.RLock()
	defer s.initMutex.RUnlock()
	return s.initialized
}

// AddResource adds a resource to the server
func (s *DefaultServer) AddResource(resource Resource) {
	s.resourcesMutex.Lock()
	defer s.resourcesMutex.Unlock()

	// Check if resource already exists
	for i, r := range s.resources {
		if r.URI == resource.URI {
			// Replace existing resource
			s.resources[i] = resource
			return
		}
	}

	// Add new resource
	s.resources = append(s.resources, resource)
}

// AddPrompt adds a prompt to the server
func (s *DefaultServer) AddPrompt(prompt Prompt) {
	s.promptsMutex.Lock()
	defer s.promptsMutex.Unlock()

	// Check if prompt already exists
	for i, p := range s.prompts {
		if p.Name == prompt.Name {
			// Replace existing prompt
			s.prompts[i] = prompt
			return
		}
	}

	// Add new prompt
	s.prompts = append(s.prompts, prompt)
}

// AddTool adds a tool to the server
func (s *DefaultServer) AddTool(tool Tool, handler ToolHandler) {
	s.toolsMutex.Lock()
	defer s.toolsMutex.Unlock()

	// Check if tool already exists
	for i, t := range s.tools {
		if t.Name == tool.Name {
			// Replace existing tool
			s.tools[i] = tool
			s.toolHandlers[t.Name] = handler
			return
		}
	}

	// Add new tool
	s.tools = append(s.tools, tool)
	s.toolHandlers[tool.Name] = handler
}

// Handle processes incoming JSON-RPC requests and returns appropriate responses
func (s *DefaultServer) Handle(requestBytes []byte) ([]byte, error) {
	// Check if it's a batch request (array) or single request
	if len(requestBytes) > 0 && requestBytes[0] == '[' {
		// It's a batch request
		return s.handleBatchRequest(requestBytes)
	}

	// It's a single request or notification
	return s.handleSingleRequest(requestBytes)
}

// handleBatchRequest processes a batch of JSON-RPC requests and returns a batch of responses
func (s *DefaultServer) handleBatchRequest(requestBytes []byte) ([]byte, error) {
	// Unmarshal the batch request
	var batchRequest []json.RawMessage
	if err := json.Unmarshal(requestBytes, &batchRequest); err != nil {
		// Invalid JSON
		return s.createErrorResponse(nil, ParseError, "Invalid JSON batch", nil)
	}

	// Empty batch is invalid according to JSON-RPC 2.0
	if len(batchRequest) == 0 {
		return s.createErrorResponse(nil, InvalidRequest, "Empty batch request", nil)
	}

	// Process each request in the batch
	var batchResponse []json.RawMessage
	for _, requestItemBytes := range batchRequest {
		responseBytes, err := s.handleSingleRequest(requestItemBytes)
		if err != nil {
			// Log the error but continue processing the batch
			fmt.Printf("Error handling batch item: %v\n", err)
		}

		// Only add responses for requests (not notifications) to the batch response
		if responseBytes != nil {
			batchResponse = append(batchResponse, responseBytes)
		}
	}

	// If all requests were notifications, return no response
	if len(batchResponse) == 0 {
		return nil, nil
	}

	// Marshal the batch response
	return json.Marshal(batchResponse)
}

// handleSingleRequest processes a single JSON-RPC request or notification
func (s *DefaultServer) handleSingleRequest(requestBytes []byte) ([]byte, error) {
	// Check if it's a JSON-RPC request or notification
	var msg struct {
		JSONRPC string     `json:"jsonrpc"`
		ID      *RequestID `json:"id,omitempty"`
		Method  string     `json:"method"`
	}

	if err := json.Unmarshal(requestBytes, &msg); err != nil {
		// Invalid JSON
		return s.createErrorResponse(nil, ParseError, "Invalid JSON", nil)
	}

	if msg.JSONRPC != JSONRPCVersion {
		// Invalid JSON-RPC version
		return s.createErrorResponse(nil, InvalidRequest, "Invalid JSON-RPC version", nil)
	}

	// Check if it's a request or notification
	if msg.ID != nil {
		// It's a request
		var request JSONRPCRequest
		if err := json.Unmarshal(requestBytes, &request); err != nil {
			return s.createErrorResponse(msg.ID, ParseError, "Invalid JSON-RPC request", nil)
		}

		// Find the appropriate handler
		handler, ok := s.requestHandlers[request.Method]
		if !ok {
			return s.createErrorResponse(msg.ID, MethodNotFound, fmt.Sprintf("Method not found: %s", request.Method), nil)
		}

		// Call the handler
		result, err := handler(*msg.ID, request.Params)
		if err != nil {
			return s.createErrorResponse(msg.ID, InternalError, err.Error(), nil)
		}

		// Marshal the result to a general JSON object
		resultBytes, err := json.Marshal(result)
		if err != nil {
			return s.createErrorResponse(msg.ID, InternalError, "Error marshaling result", nil)
		}

		// Create the response
		response := struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      RequestID       `json:"id"`
			Result  json.RawMessage `json:"result"`
		}{
			JSONRPC: JSONRPCVersion,
			ID:      *msg.ID,
			Result:  resultBytes,
		}

		// Marshal the response
		responseBytes, err := json.Marshal(response)
		if err != nil {
			return s.createErrorResponse(msg.ID, InternalError, "Error marshaling response", nil)
		}

		return responseBytes, nil
	} else {
		// It's a notification
		var notification JSONRPCNotification
		if err := json.Unmarshal(requestBytes, &notification); err != nil {
			// We don't send error responses for notifications
			return nil, fmt.Errorf("invalid JSON-RPC notification: %w", err)
		}

		// Find the appropriate handler
		handler, ok := s.notificationHandlers[notification.Method]
		if !ok {
			// We don't send error responses for notifications with unknown methods
			return nil, nil
		}

		// Call the handler
		err := handler(notification.Params)
		if err != nil {
			// We don't send error responses for notifications with errors
			return nil, fmt.Errorf("error handling notification: %w", err)
		}

		// No response for notifications
		return nil, nil
	}
}

// createErrorResponse creates a JSON-RPC error response
func (s *DefaultServer) createErrorResponse(id *RequestID, code int, message string, data interface{}) ([]byte, error) {
	// If ID is nil, use null as the ID
	var effectiveID interface{} = nil
	if id != nil {
		effectiveID = *id
	}

	response := JSONRPCError{
		JSONRPC: JSONRPCVersion,
		ID:      effectiveID,
		Error: struct {
			Code    int         `json:"code"`
			Message string      `json:"message"`
			Data    interface{} `json:"data,omitempty"`
		}{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}

	// Marshal the response
	responseBytes, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("error marshaling error response: %w", err)
	}

	return responseBytes, nil
}

// SetAuthConfig sets the authentication configuration for the server
func (s *DefaultServer) SetAuthConfig(config *AuthConfig) {
	s.authConfig = config
}

// validateAuth checks if the request is authenticated
func (s *DefaultServer) validateAuth(r *http.Request) bool {
	// If auth is not required, always allow
	if s.authConfig == nil || !s.authConfig.Required {
		return true
	}

	// Get credentials from the request
	username, password, ok := r.BasicAuth()
	if !ok {
		return false
	}

	// If a custom validator is provided, use it
	if s.authConfig.Validator != nil {
		return s.authConfig.Validator(username, password)
	}

	// Otherwise check against configured credentials
	return username == s.authConfig.Username && password == s.authConfig.Password
}

// Start starts the HTTP server to listen for MCP requests
func (s *DefaultServer) Start(address string) error {
	// Create a handler for MCP requests
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only accept POST requests
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Check authentication if required
		if !s.validateAuth(r) {
			w.Header().Set("WWW-Authenticate", "Basic realm=\"MCP Server\"")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Read the request body
		requestBytes := make([]byte, r.ContentLength)
		_, err := r.Body.Read(requestBytes)
		if err != nil && err.Error() != "EOF" {
			http.Error(w, "Error reading request body", http.StatusBadRequest)
			return
		}

		// Process the request
		responseBytes, err := s.Handle(requestBytes)
		if err != nil {
			// If this was a notification, there's no response
			if responseBytes == nil {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// If there's no response (notification), return 204 No Content
		if responseBytes == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Set the content type and write the response
		w.Header().Set("Content-Type", "application/json")
		w.Write(responseBytes)
	})

	// Create the HTTP server
	s.httpServer = &http.Server{
		Addr:    address,
		Handler: handler,
	}

	// Start the server
	return s.httpServer.ListenAndServe()
}

// Stop stops the HTTP server
func (s *DefaultServer) Stop() error {
	if s.httpServer != nil {
		return s.httpServer.Close()
	}
	return nil
}
