package mcp

import (
	"encoding/json"
)

// Constants from the TypeScript schema
const (
	LatestProtocolVersion = "2025-03-26"
	JSONRPCVersion        = "2.0"

	// Standard JSON-RPC error codes
	ParseError     = -32700
	InvalidRequest = -32600
	MethodNotFound = -32601
	InvalidParams  = -32602
	InternalError  = -32603
)

// ProgressToken is used to associate progress notifications with the original request.
type ProgressToken interface{} // Can be string or number

// Cursor is an opaque token used to represent a cursor for pagination.
type Cursor string

// RequestID is a uniquely identifying ID for a request in JSON-RPC.
type RequestID interface{} // Can be string or number

// Role is the sender or recipient of messages and data in a conversation.
type Role string

const (
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
)

// LoggingLevel represents the severity of a log message.
type LoggingLevel string

const (
	LogLevelDebug     LoggingLevel = "debug"
	LogLevelInfo      LoggingLevel = "info"
	LogLevelNotice    LoggingLevel = "notice"
	LogLevelWarning   LoggingLevel = "warning"
	LogLevelError     LoggingLevel = "error"
	LogLevelCritical  LoggingLevel = "critical"
	LogLevelAlert     LoggingLevel = "alert"
	LogLevelEmergency LoggingLevel = "emergency"
)

// Basic JSON-RPC types

// Meta contains additional metadata for requests, notifications, and responses
type Meta map[string]interface{}

// Request is the base interface for all requests
type Request struct {
	Method string                 `json:"method"`
	Params map[string]interface{} `json:"params,omitempty"`
}

// Notification is the base interface for all notifications
type Notification struct {
	Method string                 `json:"method"`
	Params map[string]interface{} `json:"params,omitempty"`
}

// Result is the base interface for all results
type Result struct {
	Meta map[string]interface{} `json:"_meta,omitempty"`
}

// JSONRPCRequest is a request that expects a response
type JSONRPCRequest struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      RequestID `json:"id"`
	Request
}

// JSONRPCNotification is a notification which does not expect a response
type JSONRPCNotification struct {
	JSONRPC string `json:"jsonrpc"`
	Notification
}

// JSONRPCResponse is a successful (non-error) response to a request
type JSONRPCResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      RequestID `json:"id"`
	Result  Result    `json:"result"`
}

// JSONRPCError is a response to a request that indicates an error occurred
type JSONRPCError struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      RequestID `json:"id"`
	Error   struct {
		Code    int         `json:"code"`
		Message string      `json:"message"`
		Data    interface{} `json:"data,omitempty"`
	} `json:"error"`
}

// JSONRPCBatchRequest is a batch of requests or notifications
type JSONRPCBatchRequest []interface{} // Can be JSONRPCRequest or JSONRPCNotification

// JSONRPCBatchResponse is a batch of responses or errors
type JSONRPCBatchResponse []interface{} // Can be JSONRPCResponse or JSONRPCError

// JSONRPCMessage is any valid JSON-RPC message
type JSONRPCMessage interface{} // Can be JSONRPCRequest, JSONRPCNotification, JSONRPCResponse, JSONRPCError, JSONRPCBatchRequest, or JSONRPCBatchResponse

// EmptyResult is a response that indicates success but carries no data
type EmptyResult Result

// Cancellation

// CancelledNotification can be sent by either side to cancel a previously-issued request
type CancelledNotification struct {
	Method string `json:"method"`
	Params struct {
		RequestID RequestID `json:"requestId"`
		Reason    string    `json:"reason,omitempty"`
	} `json:"params"`
}

// Initialization

// Implementation describes the name and version of an MCP implementation
type Implementation struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ClientCapabilities represents capabilities a client may support
type ClientCapabilities struct {
	Experimental map[string]interface{} `json:"experimental,omitempty"`
	Roots        *struct {
		ListChanged bool `json:"listChanged,omitempty"`
	} `json:"roots,omitempty"`
	Sampling interface{} `json:"sampling,omitempty"`
}

// ServerCapabilities represents capabilities that a server may support
type ServerCapabilities struct {
	Experimental map[string]interface{} `json:"experimental,omitempty"`
	Completions  interface{}            `json:"completions,omitempty"`
	Logging      interface{}            `json:"logging,omitempty"`
	Prompts      *struct {
		ListChanged bool `json:"listChanged,omitempty"`
	} `json:"prompts,omitempty"`
	Resources *struct {
		Subscribe   bool `json:"subscribe,omitempty"`
		ListChanged bool `json:"listChanged,omitempty"`
	} `json:"resources,omitempty"`
	Tools *struct {
		ListChanged bool `json:"listChanged,omitempty"`
	} `json:"tools,omitempty"`
	ProtocolVersion string `json:"protocolVersion"`
}

// InitializeRequest is sent from the client to the server when it first connects
type InitializeRequest struct {
	Method string `json:"method"`
	Params struct {
		ProtocolVersion string             `json:"protocolVersion"`
		Capabilities    ClientCapabilities `json:"capabilities"`
		ClientInfo      Implementation     `json:"clientInfo"`
	} `json:"params"`
}

// InitializeResult is sent from the server after receiving an initialize request
type InitializeResult struct {
	Result
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ServerCapabilities `json:"capabilities"`
	ServerInfo      Implementation     `json:"serverInfo"`
	Instructions    string             `json:"instructions,omitempty"`
}

// InitializedNotification is sent from the client after initialization has finished
type InitializedNotification struct {
	Method string                 `json:"method"`
	Params map[string]interface{} `json:"params,omitempty"`
}

// Ping

// PingRequest is a ping, issued by either the server or the client, to check that the other party is still alive
type PingRequest struct {
	Method string                 `json:"method"`
	Params map[string]interface{} `json:"params,omitempty"`
}

// Progress notifications

// ProgressNotification is used to inform the receiver of a progress update for a long-running request
type ProgressNotification struct {
	Method string `json:"method"`
	Params struct {
		ProgressToken ProgressToken `json:"progressToken"`
		Progress      float64       `json:"progress"`
		Total         float64       `json:"total,omitempty"`
		Message       string        `json:"message,omitempty"`
	} `json:"params"`
}

// Pagination

// PaginatedRequest extends the base Request with cursor-based pagination
type PaginatedRequest struct {
	Method string `json:"method"`
	Params struct {
		Cursor Cursor `json:"cursor,omitempty"`
	} `json:"params,omitempty"`
}

// PaginatedResult extends the base Result with cursor-based pagination
type PaginatedResult struct {
	Result
	NextCursor Cursor `json:"nextCursor,omitempty"`
}

// Annotation for resources and content
type Annotations struct {
	Audience []Role   `json:"audience,omitempty"`
	Priority *float64 `json:"priority,omitempty"`
}

// Annotated is the base for objects that include optional annotations for the client
type Annotated struct {
	Annotations *Annotations `json:"annotations,omitempty"`
}

// Resources

// ResourceContents represents the contents of a specific resource or sub-resource
type ResourceContents struct {
	URI      string `json:"uri"`
	MIMEType string `json:"mimeType,omitempty"`
}

// TextResourceContents contains text data for a resource
type TextResourceContents struct {
	ResourceContents
	Text string `json:"text"`
}

// BlobResourceContents contains binary data for a resource
type BlobResourceContents struct {
	ResourceContents
	Blob string `json:"blob"` // base64-encoded string
}

// Resource represents a known resource that the server is capable of reading
type Resource struct {
	Annotated
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MIMEType    string `json:"mimeType,omitempty"`
	Size        int64  `json:"size,omitempty"`
}

// ResourceTemplate is a template description for resources available on the server
type ResourceTemplate struct {
	Annotated
	URITemplate string `json:"uriTemplate"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MIMEType    string `json:"mimeType,omitempty"`
}

// ListResourcesRequest is sent from the client to request a list of resources
type ListResourcesRequest struct {
	Method string `json:"method"`
	Params struct {
		Cursor Cursor `json:"cursor,omitempty"`
	} `json:"params,omitempty"`
}

// ListResourcesResult is the server's response to a resources/list request
type ListResourcesResult struct {
	PaginatedResult
	Resources []Resource `json:"resources"`
}

// ListResourceTemplatesRequest is sent from the client to request resource templates
type ListResourceTemplatesRequest struct {
	Method string `json:"method"`
	Params struct {
		Cursor Cursor `json:"cursor,omitempty"`
	} `json:"params,omitempty"`
}

// ListResourceTemplatesResult is the server's response to a resources/templates/list request
type ListResourceTemplatesResult struct {
	PaginatedResult
	ResourceTemplates []ResourceTemplate `json:"resourceTemplates"`
}

// ReadResourceRequest is sent to read a specific resource URI
type ReadResourceRequest struct {
	Method string `json:"method"`
	Params struct {
		URI string `json:"uri"`
	} `json:"params"`
}

// ReadResourceResult is the server's response to a resources/read request
type ReadResourceResult struct {
	Result
	Contents []json.RawMessage `json:"contents"` // Can be TextResourceContents or BlobResourceContents
}

// ResourceListChangedNotification informs the client that resources have changed
type ResourceListChangedNotification struct {
	Method string                 `json:"method"`
	Params map[string]interface{} `json:"params,omitempty"`
}

// SubscribeRequest requests notifications for resource changes
type SubscribeRequest struct {
	Method string `json:"method"`
	Params struct {
		URI string `json:"uri"`
	} `json:"params"`
}

// UnsubscribeRequest cancels notifications for resource changes
type UnsubscribeRequest struct {
	Method string `json:"method"`
	Params struct {
		URI string `json:"uri"`
	} `json:"params"`
}

// ResourceUpdatedNotification informs the client that a resource has been updated
type ResourceUpdatedNotification struct {
	Method string `json:"method"`
	Params struct {
		URI string `json:"uri"`
	} `json:"params"`
}

// Prompts

// PromptArgument describes an argument that a prompt can accept
type PromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// Prompt represents a prompt or prompt template that the server offers
type Prompt struct {
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Arguments   []PromptArgument `json:"arguments,omitempty"`
}

// Content structures
type ContentType string

const (
	ContentTypeText     ContentType = "text"
	ContentTypeImage    ContentType = "image"
	ContentTypeAudio    ContentType = "audio"
	ContentTypeResource ContentType = "resource"
)

// TextContent represents text provided to or from an LLM
type TextContent struct {
	Annotated
	Type ContentType `json:"type"`
	Text string      `json:"text"`
}

// ImageContent represents an image provided to or from an LLM
type ImageContent struct {
	Annotated
	Type     ContentType `json:"type"`
	Data     string      `json:"data"` // base64-encoded
	MIMEType string      `json:"mimeType"`
}

// AudioContent represents audio provided to or from an LLM
type AudioContent struct {
	Annotated
	Type     ContentType `json:"type"`
	Data     string      `json:"data"` // base64-encoded
	MIMEType string      `json:"mimeType"`
}

// EmbeddedResource represents a resource embedded into a prompt or tool call result
type EmbeddedResource struct {
	Annotated
	Type     ContentType     `json:"type"`
	Resource json.RawMessage `json:"resource"` // TextResourceContents or BlobResourceContents
}

// PromptMessage describes a message returned as part of a prompt
type PromptMessage struct {
	Role    Role            `json:"role"`
	Content json.RawMessage `json:"content"` // TextContent, ImageContent, AudioContent or EmbeddedResource
}

// ListPromptsRequest requests a list of prompts and prompt templates
type ListPromptsRequest struct {
	Method string `json:"method"`
	Params struct {
		Cursor Cursor `json:"cursor,omitempty"`
	} `json:"params,omitempty"`
}

// ListPromptsResult is the server's response to a prompts/list request
type ListPromptsResult struct {
	PaginatedResult
	Prompts []Prompt `json:"prompts"`
}

// GetPromptRequest is used to get a prompt provided by the server
type GetPromptRequest struct {
	Method string `json:"method"`
	Params struct {
		Name      string            `json:"name"`
		Arguments map[string]string `json:"arguments,omitempty"`
	} `json:"params"`
}

// GetPromptResult is the server's response to a prompts/get request
type GetPromptResult struct {
	Result
	Description string          `json:"description,omitempty"`
	Messages    []PromptMessage `json:"messages"`
}

// PromptListChangedNotification informs that the list of prompts has changed
type PromptListChangedNotification struct {
	Method string                 `json:"method"`
	Params map[string]interface{} `json:"params,omitempty"`
}

// Tools

// ToolAnnotations provides additional properties describing a Tool to clients
type ToolAnnotations struct {
	Title           string `json:"title,omitempty"`           // A human-readable title for the tool
	ReadOnlyHint    bool   `json:"readOnlyHint,omitempty"`    // If true, the tool does not modify its environment
	DestructiveHint bool   `json:"destructiveHint,omitempty"` // If true, the tool may perform destructive updates
	IdempotentHint  bool   `json:"idempotentHint,omitempty"`  // If true, calling the tool repeatedly with the same arguments has no additional effect
	OpenWorldHint   bool   `json:"openWorldHint,omitempty"`   // If true, this tool may interact with an "open world" of external entities
}

// Tool defines a tool the client can call
type Tool struct {
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Annotations *ToolAnnotations `json:"annotations,omitempty"`
	InputSchema struct {
		Type       string                     `json:"type"`
		Properties map[string]json.RawMessage `json:"properties,omitempty"`
		Required   []string                   `json:"required,omitempty"`
	} `json:"inputSchema"`
}

// ListToolsRequest requests a list of tools
type ListToolsRequest struct {
	Method string `json:"method"`
	Params struct {
		Cursor Cursor `json:"cursor,omitempty"`
	} `json:"params,omitempty"`
}

// ListToolsResult is the server's response to a tools/list request
type ListToolsResult struct {
	PaginatedResult
	Tools []Tool `json:"tools"`
}

// CallToolRequest is used to invoke a tool provided by the server
type CallToolRequest struct {
	Method string `json:"method"`
	Params struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments,omitempty"`
	} `json:"params"`
}

// CallToolResult is the server's response to a tool call
type CallToolResult struct {
	Result
	Content []json.RawMessage `json:"content"` // TextContent, ImageContent, AudioContent or EmbeddedResource
	IsError bool              `json:"isError,omitempty"`
}

// ToolListChangedNotification informs that the list of tools has changed
type ToolListChangedNotification struct {
	Method string                 `json:"method"`
	Params map[string]interface{} `json:"params,omitempty"`
}

// Logging

// SetLevelRequest enables or adjusts logging
type SetLevelRequest struct {
	Method string `json:"method"`
	Params struct {
		Level LoggingLevel `json:"level"`
	} `json:"params"`
}

// LoggingMessageNotification passes a log message from server to client
type LoggingMessageNotification struct {
	Method string `json:"method"`
	Params struct {
		Level  LoggingLevel `json:"level"`
		Logger string       `json:"logger,omitempty"`
		Data   interface{}  `json:"data"`
	} `json:"params"`
}

// Sampling

// SamplingMessage describes a message issued to or received from an LLM API
type SamplingMessage struct {
	Role    Role            `json:"role"`
	Content json.RawMessage `json:"content"` // TextContent, ImageContent, or AudioContent
}

// ModelHint provides hints for model selection
type ModelHint struct {
	Name string `json:"name,omitempty"`
}

// ModelPreferences expresses server priorities for model selection during sampling
type ModelPreferences struct {
	Hints                []ModelHint `json:"hints,omitempty"`
	CostPriority         *float64    `json:"costPriority,omitempty"`
	SpeedPriority        *float64    `json:"speedPriority,omitempty"`
	IntelligencePriority *float64    `json:"intelligencePriority,omitempty"`
}

// CreateMessageRequest samples an LLM via the client
type CreateMessageRequest struct {
	Method string `json:"method"`
	Params struct {
		Messages         []SamplingMessage `json:"messages"`
		ModelPreferences *ModelPreferences `json:"modelPreferences,omitempty"`
		SystemPrompt     string            `json:"systemPrompt,omitempty"`
		IncludeContext   string            `json:"includeContext,omitempty"` // "none", "thisServer", "allServers"
		Temperature      *float64          `json:"temperature,omitempty"`
		MaxTokens        int               `json:"maxTokens"`
		StopSequences    []string          `json:"stopSequences,omitempty"`
		Metadata         interface{}       `json:"metadata,omitempty"`
	} `json:"params"`
}

// CreateMessageResult is the client's response to a sampling/create_message request
type CreateMessageResult struct {
	Result
	Role       Role            `json:"role"`
	Content    json.RawMessage `json:"content"` // TextContent, ImageContent, or AudioContent
	Model      string          `json:"model"`
	StopReason string          `json:"stopReason,omitempty"`
}

// Autocomplete

// ResourceReference references a resource or resource template
type ResourceReference struct {
	Type string `json:"type"` // "ref/resource"
	URI  string `json:"uri"`
}

// PromptReference identifies a prompt
type PromptReference struct {
	Type string `json:"type"` // "ref/prompt"
	Name string `json:"name"`
}

// CompleteRequest asks for completion options
type CompleteRequest struct {
	Method string `json:"method"`
	Params struct {
		Ref      json.RawMessage `json:"ref"` // PromptReference or ResourceReference
		Argument struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"argument"`
	} `json:"params"`
}

// CompleteResult is the server's response to a completion/complete request
type CompleteResult struct {
	Result
	Completion struct {
		Values  []string `json:"values"`
		Total   int      `json:"total,omitempty"`
		HasMore bool     `json:"hasMore,omitempty"`
	} `json:"completion"`
}

// Roots

// Root represents a root directory or file that the server can operate on
type Root struct {
	URI  string `json:"uri"`
	Name string `json:"name,omitempty"`
}

// ListRootsRequest requests a list of root URIs from the client
type ListRootsRequest struct {
	Method string                 `json:"method"`
	Params map[string]interface{} `json:"params,omitempty"`
}

// ListRootsResult is the client's response to a roots/list request
type ListRootsResult struct {
	Result
	Roots []Root `json:"roots"`
}

// RootsListChangedNotification informs that the list of roots has changed
type RootsListChangedNotification struct {
	Method string                 `json:"method"`
	Params map[string]interface{} `json:"params,omitempty"`
}

// Helper functions for unmarshaling content types

// UnmarshalContent unmarshals content from JSON
func UnmarshalContent(data []byte) (interface{}, error) {
	// First unmarshal to get the type
	var typeContainer struct {
		Type ContentType `json:"type"`
	}
	if err := json.Unmarshal(data, &typeContainer); err != nil {
		return nil, err
	}

	switch typeContainer.Type {
	case ContentTypeText:
		var content TextContent
		if err := json.Unmarshal(data, &content); err != nil {
			return nil, err
		}
		return content, nil
	case ContentTypeImage:
		var content ImageContent
		if err := json.Unmarshal(data, &content); err != nil {
			return nil, err
		}
		return content, nil
	case ContentTypeAudio:
		var content AudioContent
		if err := json.Unmarshal(data, &content); err != nil {
			return nil, err
		}
		return content, nil
	case ContentTypeResource:
		var content EmbeddedResource
		if err := json.Unmarshal(data, &content); err != nil {
			return nil, err
		}
		return content, nil
	default:
		return nil, nil
	}
}

// UnmarshalReference unmarshals a reference from JSON
func UnmarshalReference(data []byte) (interface{}, error) {
	// First unmarshal to get the type
	var typeContainer struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &typeContainer); err != nil {
		return nil, err
	}

	switch typeContainer.Type {
	case "ref/resource":
		var ref ResourceReference
		if err := json.Unmarshal(data, &ref); err != nil {
			return nil, err
		}
		return ref, nil
	case "ref/prompt":
		var ref PromptReference
		if err := json.Unmarshal(data, &ref); err != nil {
			return nil, err
		}
		return ref, nil
	default:
		return nil, nil
	}
}

// UnmarshalResourceContents unmarshals resource contents from JSON
func UnmarshalResourceContents(data []byte) (interface{}, error) {
	// Try to unmarshal as TextResourceContents
	var textContent TextResourceContents
	if err := json.Unmarshal(data, &textContent); err == nil {
		if textContent.Text != "" {
			return textContent, nil
		}
	}

	// Try to unmarshal as BlobResourceContents
	var blobContent BlobResourceContents
	if err := json.Unmarshal(data, &blobContent); err == nil {
		if blobContent.Blob != "" {
			return blobContent, nil
		}
	}

	return nil, nil
}
