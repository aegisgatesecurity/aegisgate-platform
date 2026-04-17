// Package tool-executor - Database tool implementations
package toolexecutor

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DatabaseTools provides database operation tools
type DatabaseTools struct {
	allowedConnections map[string]*sql.DB
	timeout          time.Duration
}

// NewDatabaseTools creates a new database tools executor
func NewDatabaseTools(timeout time.Duration) *DatabaseTools {
	return &DatabaseTools{
		allowedConnections: make(map[string]*sql.DB),
		timeout:          timeout,
	}
}

// RegisterConnection registers a database connection
func (t *DatabaseTools) RegisterConnection(name string, db *sql.DB) {
	t.allowedConnections[name] = db
}

// DatabaseQueryExecutor handles database query operations
type DatabaseQueryExecutor struct {
	tools *DatabaseTools
}

// NewDatabaseQueryExecutor creates a new database query executor
func NewDatabaseQueryExecutor(tools *DatabaseTools) *DatabaseQueryExecutor {
	return &DatabaseQueryExecutor{tools: tools}
}

// Name returns the tool name
func (e *DatabaseQueryExecutor) Name() string {
	return "database_query"
}

// Execute runs a database query
func (e *DatabaseQueryExecutor) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	connectionName, ok := params["connection"].(string)
	if !ok || connectionName == "" {
		return nil, errors.New("connection parameter required")
	}

	query, ok := params["query"].(string)
	if !ok || query == "" {
		return nil, errors.New("query parameter required")
	}

	// Security: validate query
	if err := e.validateQuery(query); err != nil {
		return nil, err
	}

	// Get connection
	db, exists := e.tools.allowedConnections[connectionName]
	if !exists {
		return nil, fmt.Errorf("database connection not found: %s", connectionName)
	}

	// Execute query with timeout
	queryCtx, cancel := context.WithTimeout(ctx, e.tools.timeout)
	defer cancel()

	// Check if it's a SELECT query
	queryUpper := strings.ToUpper(strings.TrimSpace(query))
	isSelect := strings.HasPrefix(queryUpper, "SELECT") || strings.HasPrefix(queryUpper, "SHOW") || strings.HasPrefix(queryUpper, "DESCRIBE")

	var result interface{}

	if isSelect {
		rows, err := db.QueryContext(queryCtx, query)
		if err != nil {
			return nil, err
		}
		defer rows.Close()

		// Get column names
		columns, err := rows.Columns()
		if err != nil {
			return nil, err
		}

		// Fetch rows
		var results []map[string]interface{}
		for rows.Next() {
			values := make([]interface{}, len(columns))
			valuePtrs := make([]interface{}, len(columns))
			for i := range values {
				valuePtrs[i] = &values[i]
			}

			if err := rows.Scan(valuePtrs...); err != nil {
				return nil, err
			}

			row := make(map[string]interface{})
			for i, col := range columns {
				row[col] = values[i]
			}
			results = append(results, row)
		}

		result = map[string]interface{}{
			"columns": columns,
			"rows":    results,
			"count":   len(results),
		}
	} else {
		// Execute statement (INSERT, UPDATE, DELETE)
		resultExec, err := db.ExecContext(queryCtx, query)
		if err != nil {
			return nil, err
		}

		rowsAffected, _ := resultExec.RowsAffected()
		lastID, _ := resultExec.LastInsertId()

		result = map[string]interface{}{
			"rows_affected": rowsAffected,
			"last_insert_id": lastID,
		}
	}

	return result, nil
}

// Validate checks parameters
func (e *DatabaseQueryExecutor) Validate(params map[string]interface{}) error {
	query, ok := params["query"].(string)
	if !ok || query == "" {
		return errors.New("query parameter required")
	}

	return e.validateQuery(query)
}

// validateQuery validates the SQL query for safety
func (e *DatabaseQueryExecutor) validateQuery(query string) error {
	// Block dangerous operations
	upperQuery := strings.ToUpper(query)

	// Block data modification on sensitive tables (configurable)
	sensitive := []string{"DROP", "TRUNCATE", "ALTER", "CREATE"}
	for _, op := range sensitive {
		if strings.Contains(upperQuery, op) {
			return fmt.Errorf("query contains forbidden operation: %s", op)
		}
	}

	// Block multiple statements (SQL injection prevention)
	if strings.Contains(query, ";") {
		parts := strings.Split(query, ";")
		if len(strings.TrimSpace(parts[len(parts)-1])) > 0 {
			return errors.New("multiple statements not allowed")
		}
	}

	return nil
}

// Timeout returns the execution timeout
func (e *DatabaseQueryExecutor) Timeout() time.Duration {
	return e.tools.timeout
}

// RiskLevel returns the risk level
func (e *DatabaseQueryExecutor) RiskLevel() int {
	return int(RiskHigh)
}

// Description returns a description
func (e *DatabaseQueryExecutor) Description() string {
	return "Execute database queries"
}

// DatabaseListExecutor lists available database connections
type DatabaseListExecutor struct {
	tools *DatabaseTools
}

// NewDatabaseListExecutor creates a new database list executor
func NewDatabaseListExecutor(tools *DatabaseTools) *DatabaseListExecutor {
	return &DatabaseListExecutor{tools: tools}
}

// Name returns the tool name
func (e *DatabaseListExecutor) Name() string {
	return "database_list"
}

// Execute lists available database connections
func (e *DatabaseListExecutor) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	connections := make([]string, 0, len(e.tools.allowedConnections))
	for name := range e.tools.allowedConnections {
		connections = append(connections, name)
	}

	return map[string]interface{}{
		"connections": connections,
		"count":      len(connections),
	}, nil
}

// Validate checks parameters
func (e *DatabaseListExecutor) Validate(params map[string]interface{}) error {
	return nil // No parameters required
}

// Timeout returns the execution timeout
func (e *DatabaseListExecutor) Timeout() time.Duration {
	return 5 * time.Second
}

// RiskLevel returns the risk level
func (e *DatabaseListExecutor) RiskLevel() int {
	return int(RiskLow)
}

// Description returns a description
func (e *DatabaseListExecutor) Description() string {
	return "List available database connections"
}

// DatabaseSchemaExecutor retrieves database schema
type DatabaseSchemaExecutor struct {
	tools *DatabaseTools
}

// NewDatabaseSchemaExecutor creates a new database schema executor
func NewDatabaseSchemaExecutor(tools *DatabaseTools) *DatabaseSchemaExecutor {
	return &DatabaseSchemaExecutor{tools: tools}
}

// Name returns the tool name
func (e *DatabaseSchemaExecutor) Name() string {
	return "database_schema"
}

// Execute retrieves database schema
func (e *DatabaseSchemaExecutor) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	connectionName, ok := params["connection"].(string)
	if !ok || connectionName == "" {
		return nil, errors.New("connection parameter required")
	}

	db, exists := e.tools.allowedConnections[connectionName]
	if !exists {
		return nil, fmt.Errorf("database connection not found: %s", connectionName)
	}

	// Execute with timeout
	queryCtx, cancel := context.WithTimeout(ctx, e.tools.timeout)
	defer cancel()

	// Get tables (generic - works with most SQL databases)
	rows, err := db.QueryContext(queryCtx, `
		SELECT table_name, table_schema 
		FROM information_schema.tables 
		WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
		ORDER BY table_schema, table_name
	`)
	if err != nil {
		// Try SQLite fallback
		rows, err = db.QueryContext(queryCtx, "SELECT name, '' as table_schema FROM sqlite_master WHERE type='table'")
		if err != nil {
			return nil, err
		}
	}
	defer rows.Close()

	var tables []map[string]string
	for rows.Next() {
		var name, schema string
		if err := rows.Scan(&name, &schema); err != nil {
			continue
		}
		tables = append(tables, map[string]string{
			"name":   name,
			"schema": schema,
		})
	}

	return map[string]interface{}{
		"tables": tables,
		"count":  len(tables),
	}, nil
}

// Validate checks parameters
func (e *DatabaseSchemaExecutor) Validate(params map[string]interface{}) error {
	connectionName, ok := params["connection"].(string)
	if !ok || connectionName == "" {
		return errors.New("connection parameter required")
	}
	return nil
}

// Timeout returns the execution timeout
func (e *DatabaseSchemaExecutor) Timeout() time.Duration {
	return 30 * time.Second
}

// RiskLevel returns the risk level
func (e *DatabaseSchemaExecutor) RiskLevel() int {
	return int(RiskMedium)
}

// Description returns a description
func (e *DatabaseSchemaExecutor) Description() string {
	return "Get database schema information"
}
