package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
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

	// Logger for structured logging
	logger *slog.Logger
}

// RequestHandler defines a function that handles a JSON-RPC request
type RequestHandler func(id RequestID, params map[string]interface{}) (interface{}, error)

// NotificationHandler defines a function that handles a JSON-RPC notification
type NotificationHandler func(params map[string]interface{}) error

// ToolHandler defines a function that handles a tool call
type ToolHandler func(arguments map[string]interface{}) (string, error)

// NewServer creates a new MCP server with the given configuration
func NewServer(serverInfo Implementation, capabilities ServerCapabilities) *DefaultServer {

	s := &DefaultServer{
		serverInfo:           serverInfo,
		capabilities:         capabilities,
		requestHandlers:      make(map[string]RequestHandler),
		notificationHandlers: make(map[string]NotificationHandler),
		toolHandlers:         make(map[string]ToolHandler),
		logger: slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})),
	}

	s.registerRequestHandlers()
	return s
}

func NewServerWithLogger(serverInfo Implementation, capabilities ServerCapabilities, logger *slog.Logger) *DefaultServer {
	s := NewServer(serverInfo, capabilities)
	s.logger = logger
	return s
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
	s.logger.Debug("registering request handlers")

	// Initialize request
	s.requestHandlers["initialize"] = func(id RequestID, params map[string]interface{}) (interface{}, error) {
		s.logger.Debug("received initialize request")

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
		s.logger.Info("initialized", "protocol_version", initParams.ProtocolVersion)

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
		s.logger.Debug("received ping request")

		return EmptyResult{}, nil
	}

	// List resources request
	s.requestHandlers["resources/list"] = func(id RequestID, params map[string]interface{}) (interface{}, error) {
		s.logger.Debug("received resources/list request")

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
		s.logger.Debug("received prompts/list request")

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
		s.logger.Debug("received tools/list request")

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
		s.logger.Debug("received tools/call request")

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
	s.logger.Debug("registering notification handlers")

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

// AddResource adds a new resource to the server
func (s *DefaultServer) AddResource(resource Resource) {
	s.resourcesMutex.Lock()
	defer s.resourcesMutex.Unlock()
	s.resources = append(s.resources, resource)
	s.logger.Info("resource added", "uri", resource.URI, "name", resource.Name)
}

// AddPrompt adds a new prompt to the server
func (s *DefaultServer) AddPrompt(prompt Prompt) {
	s.promptsMutex.Lock()
	defer s.promptsMutex.Unlock()
	s.prompts = append(s.prompts, prompt)
	s.logger.Info("prompt added", "name", prompt.Name)
}

// AddTool adds a new tool to the server
func (s *DefaultServer) AddTool(tool Tool, handler ToolHandler) {
	s.toolsMutex.Lock()
	defer s.toolsMutex.Unlock()
	s.tools = append(s.tools, tool)
	s.toolHandlers[tool.Name] = handler
	s.logger.Info("tool added", "name", tool.Name)
}

// Handle processes incoming HTTP requests
func (s *DefaultServer) Handle(w http.ResponseWriter, r *http.Request) {
	s.logger.Debug("received request", "method", r.Method, "path", r.URL.Path)

	if r.Method != http.MethodPost {
		s.logger.Warn("invalid HTTP method", "method", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.Header.Get("Content-Type") != "application/json" {
		s.logger.Warn("invalid content type", "content_type", r.Header.Get("Content-Type"))
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}

	// Validate authentication if configured
	if s.authConfig != nil {
		if !s.validateAuth(r) {
			s.logger.Warn("authentication failed")
			w.Header().Set("WWW-Authenticate", "Basic realm=\"MCP Server\"")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// Only accept POST requests to /jsonrpc endpoint
	if r.Method != http.MethodPost || r.URL.Path != "/jsonrpc" {
		http.Error(w, "Method or path not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read the request body
	requestBytes, err := io.ReadAll(r.Body)
	if err != nil {
		s.logger.Error("failed to read request body", "error", err)
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}

	// Process the request
	responseBytes, err := s.handleRequest(requestBytes)
	if err != nil {
		s.logger.Error("failed to process request", "error", err)
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
}

// handleRequest processes the raw request bytes and returns the response
func (s *DefaultServer) handleRequest(requestBytes []byte) ([]byte, error) {
	var msg interface{}
	if err := json.Unmarshal(requestBytes, &msg); err != nil {
		s.logger.Error("failed to decode request", "error", err)
		return nil, fmt.Errorf("Invalid JSON: %v", err)
	}

	// Handle batch requests
	if msgs, ok := msg.([]interface{}); ok {
		s.logger.Debug("received batch request", "count", len(msgs))
		return s.handleBatchRequest(msgs)
	}

	// Handle single request
	s.logger.Debug("received single request")
	return s.handleSingleRequest(msg)
}

// handleBatchRequest processes a batch of JSON-RPC requests
func (s *DefaultServer) handleBatchRequest(msgs []interface{}) ([]byte, error) {
	if len(msgs) == 0 {
		s.logger.Warn("empty batch request")
		return nil, fmt.Errorf("Empty batch request")
	}

	var responses []interface{}
	for _, msg := range msgs {
		// Convert the message to a JSONRPCRequest or JSONRPCNotification
		msgBytes, err := json.Marshal(msg)
		if err != nil {
			s.logger.Error("failed to marshal batch message", "error", err)
			continue
		}

		var request JSONRPCRequest
		var notification JSONRPCNotification
		if err := json.Unmarshal(msgBytes, &request); err == nil && request.ID != nil {
			// It's a request
			response, err := s.handleSingleRequest(request)
			if err != nil {
				s.logger.Error("failed to handle batch request", "error", err)
				continue
			}
			responses = append(responses, response)
		} else if err := json.Unmarshal(msgBytes, &notification); err == nil {
			// It's a notification
			if err := s.handleNotification(notification); err != nil {
				s.logger.Error("failed to handle batch notification", "error", err)
			}
		}
	}

	if len(responses) == 0 {
		return nil, nil // No responses for notifications
	}

	responseBytes, err := json.Marshal(responses)
	if err != nil {
		s.logger.Error("failed to marshal batch response", "error", err)
		return nil, fmt.Errorf("Failed to marshal batch response: %v", err)
	}

	return responseBytes, nil
}

// handleSingleRequest processes a single JSON-RPC request
func (s *DefaultServer) handleSingleRequest(msg interface{}) ([]byte, error) {
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		s.logger.Error("failed to marshal request", "error", err)
		return nil, fmt.Errorf("Failed to marshal request: %v", err)
	}

	var request JSONRPCRequest
	if err := json.Unmarshal(msgBytes, &request); err != nil {
		s.logger.Error("failed to decode request", "error", err)
		return nil, fmt.Errorf("Invalid request format: %v", err)
	}

	// Check if the server has been initialized
	if !s.isInitialized() && request.Method != "initialize" {
		s.logger.Warn("request received before initialization", "method", request.Method)
		return nil, fmt.Errorf("Server not initialized")
	}

	// Get the handler for this method
	handler, ok := s.requestHandlers[request.Method]
	if !ok {
		s.logger.Warn("method not found", "method", request.Method)
		return nil, fmt.Errorf("Method not found: %s", request.Method)
	}

	// Call the handler
	result, err := handler(request.ID, request.Params)
	if err != nil {
		s.logger.Error("handler error", "method", request.Method, "error", err)
		return nil, err
	}

	// Create the response with the result
	var response JSONRPCResponse
	if result != nil {
		// First marshal the result to JSON
		resultBytes, err := json.Marshal(result)
		if err != nil {
			s.logger.Error("failed to marshal result", "error", err)
			return nil, fmt.Errorf("Failed to marshal result: %v", err)
		}

		// Create the response with empty Result
		response = JSONRPCResponse{
			JSONRPC: JSONRPCVersion,
			ID:      request.ID,
			Result:  Result{}, // Initialize with empty Result
		}

		// Unmarshal the result bytes into the Result field
		if err := json.Unmarshal(resultBytes, &response.Result.Meta); err != nil {
			s.logger.Error("failed to unmarshal result", "error", err)
			return nil, fmt.Errorf("Failed to unmarshal result: %v", err)
		}
	} else {

		// Create response with empty Result for nil results
		response = JSONRPCResponse{
			JSONRPC: JSONRPCVersion,
			ID:      request.ID,
			Result:  Result{},
		}
	}

	// Marshal the response
	responseBytes, err := json.Marshal(response)
	if err != nil {
		s.logger.Error("failed to marshal response", "error", err)
		return nil, fmt.Errorf("Failed to marshal response: %v", err)
	}

	return responseBytes, nil
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
	s.logger.Info("authentication configured", "required", config.Required)
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
func (s *DefaultServer) Start(addr string) error {
	s.logger.Info("starting MCP server", "address", addr)

	s.httpServer = &http.Server{
		Addr:    addr,
		Handler: http.HandlerFunc(s.Handle),
	}

	s.logger.Info("server started successfully")
	return s.httpServer.ListenAndServe()
}

// Stop stops the HTTP server
func (s *DefaultServer) Stop() error {
	s.logger.Info("stopping MCP server")
	if s.httpServer != nil {
		return s.httpServer.Close()
	}
	return nil
}

// handleNotification processes a JSON-RPC notification
func (s *DefaultServer) handleNotification(notification JSONRPCNotification) error {
	// Get the handler for this method
	handler, ok := s.notificationHandlers[notification.Method]
	if !ok {
		s.logger.Warn("notification method not found", "method", notification.Method)
		return nil // We don't send error responses for notifications
	}

	// Call the handler
	err := handler(notification.Params)
	if err != nil {
		s.logger.Error("notification handler error", "method", notification.Method, "error", err)
		return err
	}

	return nil
}
