package mcp

import (
	"encoding/json"
)

// JSONRPCRequest represents an incoming JSON-RPC 2.0 request or notification.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"` // string, number, or null
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse represents an outgoing JSON-RPC 2.0 response.
type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      interface{}   `json:"id"`
	Result  interface{}   `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
}

// JSONRPCError represents a JSON-RPC 2.0 error object.
type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Standard JSON-RPC error codes
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
)

// MCP Server Information
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// MCP Capabilities
type ServerCapabilities struct {
	Tools map[string]interface{} `json:"tools"`
}

// InitializeResult is the response payload for the "initialize" method.
type InitializeResult struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ServerCapabilities `json:"capabilities"`
	ServerInfo      ServerInfo         `json:"serverInfo"`
}

// Tool definition for MCP tools/list
type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema InputSchema `json:"inputSchema"`
}

// InputSchema defines the JSON schema for tool arguments.
type InputSchema struct {
	Type       string                 `json:"type"`
	Properties map[string]PropertyDef `json:"properties"`
	Required   []string               `json:"required,omitempty"`
}

// PropertyDef describes an individual parameter property.
type PropertyDef struct {
	Type        string   `json:"type"`
	Description string   `json:"description"`
	Enum        []string `json:"enum,omitempty"`
}

// ToolCallParams represents params for tools/call.
type ToolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

// ToolContentItem represents content returned in a tool call result.
type ToolContentItem struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// ToolCallResult is the MCP result returned for tools/call.
type ToolCallResult struct {
	Content []ToolContentItem      `json:"content"`
	IsError bool                   `json:"isError"`
	Meta    map[string]interface{} `json:"meta,omitempty"`
}
