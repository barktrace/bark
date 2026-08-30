package store

import (
	"context"
	"database/sql/driver"
	"regexp"
	"strconv"
	"strings"
)

var (
	postgresBlobDefault  = regexp.MustCompile(`(?i)BLOB NOT NULL DEFAULT '([^']*)'`)
	postgresBlobType     = regexp.MustCompile(`(?i)\bBLOB\b`)
	postgresRowID        = regexp.MustCompile(`\browid\b`)
	postgresTimestamp    = regexp.MustCompile(`(?m)^(\s+[a-z_]*(?:_at|timestamp)) TEXT\b`)
	postgresNullableTime = regexp.MustCompile(`COALESCE\(([a-z_.]*(?:_at|timestamp)), ''\)`)
)

func isPostgresURL(raw string) bool {
	lower := strings.ToLower(strings.TrimSpace(raw))
	return strings.HasPrefix(lower, "postgres://") || strings.HasPrefix(lower, "postgresql://")
}

func postgresMigration(query string) string {
	query = postgresBlobDefault.ReplaceAllString(query, `BYTEA NOT NULL DEFAULT convert_to('$1', 'UTF8')`)
	query = postgresBlobType.ReplaceAllString(query, "BYTEA")
	query = postgresTimestamp.ReplaceAllString(query, "$1 TIMESTAMPTZ")
	query = strings.ReplaceAll(query, " COLLATE NOCASE", "")
	query = strings.ReplaceAll(query, "INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY")
	query = strings.Replace(query, "CREATE TABLE projects (", "CREATE TABLE projects (\n    legacy_id BIGSERIAL UNIQUE,", 1)
	query = strings.Replace(query, "CREATE TABLE issues (", "CREATE TABLE issues (\n    legacy_id BIGSERIAL UNIQUE,", 1)
	return query
}

type postgresConnector struct {
	underlying driver.Connector
}

func newPostgresConnector(connector driver.Connector) driver.Connector {
	return &postgresConnector{underlying: connector}
}

func (c *postgresConnector) Connect(ctx context.Context) (driver.Conn, error) {
	connection, err := c.underlying.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &postgresConn{underlying: connection}, nil
}

func (c *postgresConnector) Driver() driver.Driver { return c.underlying.Driver() }

type postgresConn struct {
	underlying driver.Conn
}

func (c *postgresConn) Prepare(query string) (driver.Stmt, error) {
	return c.underlying.Prepare(postgresQuery(query))
}

func (c *postgresConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	if connection, ok := c.underlying.(driver.ConnPrepareContext); ok {
		return connection.PrepareContext(ctx, postgresQuery(query))
	}
	return nil, driver.ErrSkip
}

func (c *postgresConn) Close() error              { return c.underlying.Close() }
func (c *postgresConn) Begin() (driver.Tx, error) { return c.underlying.Begin() }

func (c *postgresConn) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	if connection, ok := c.underlying.(driver.ConnBeginTx); ok {
		return connection.BeginTx(ctx, options)
	}
	return nil, driver.ErrSkip
}

func (c *postgresConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if connection, ok := c.underlying.(driver.ExecerContext); ok {
		return connection.ExecContext(ctx, postgresQuery(query), args)
	}
	return nil, driver.ErrSkip
}

func (c *postgresConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if connection, ok := c.underlying.(driver.QueryerContext); ok {
		return connection.QueryContext(ctx, postgresQuery(query), args)
	}
	return nil, driver.ErrSkip
}

func (c *postgresConn) Ping(ctx context.Context) error {
	if connection, ok := c.underlying.(driver.Pinger); ok {
		return connection.Ping(ctx)
	}
	return driver.ErrSkip
}

func (c *postgresConn) CheckNamedValue(value *driver.NamedValue) error {
	if connection, ok := c.underlying.(driver.NamedValueChecker); ok {
		return connection.CheckNamedValue(value)
	}
	return driver.ErrSkip
}

func (c *postgresConn) ResetSession(ctx context.Context) error {
	if connection, ok := c.underlying.(driver.SessionResetter); ok {
		return connection.ResetSession(ctx)
	}
	return nil
}

func (c *postgresConn) IsValid() bool {
	if connection, ok := c.underlying.(driver.Validator); ok {
		return connection.IsValid()
	}
	return true
}

func postgresQuery(query string) string {
	query = strings.ReplaceAll(query, "CAST(strftime('%s', timestamp) AS INTEGER)", "CAST(EXTRACT(EPOCH FROM timestamp) AS BIGINT)")
	query = strings.ReplaceAll(query, "CAST(strftime('%s', created_at) AS INTEGER)", "CAST(EXTRACT(EPOCH FROM created_at) AS BIGINT)")
	query = postgresNullableTime.ReplaceAllString(query, "COALESCE($1::text, '')")
	query = strings.ReplaceAll(query, " COLLATE NOCASE", "")
	query = strings.ReplaceAll(query, " LIKE ", " ILIKE ")
	query = strings.ReplaceAll(query, "s.rowid DESC", "s.id DESC")
	query = postgresRowID.ReplaceAllString(query, "legacy_id")
	query = strings.ReplaceAll(query, "GROUP_CONCAT(DISTINCT r.version)", "STRING_AGG(DISTINCT r.version, ',')")
	query = strings.ReplaceAll(query, "datetime(created_at) >= datetime(?)", "created_at::timestamptz >= ?::timestamptz")
	query = strings.ReplaceAll(query, "c.checked_at >= datetime('now', '-24 hours')", "c.checked_at::timestamptz >= CURRENT_TIMESTAMP - INTERVAL '24 hours'")
	return rebindPostgres(query)
}

func rebindPostgres(query string) string {
	var result strings.Builder
	result.Grow(len(query) + 16)
	argument := 1
	inSingleQuote := false
	inDoubleQuote := false
	for index := 0; index < len(query); index++ {
		character := query[index]
		switch character {
		case '\'':
			if !inDoubleQuote {
				if inSingleQuote && index+1 < len(query) && query[index+1] == '\'' {
					result.WriteByte(character)
					result.WriteByte(query[index+1])
					index++
					continue
				}
				inSingleQuote = !inSingleQuote
			}
			result.WriteByte(character)
		case '"':
			if !inSingleQuote {
				inDoubleQuote = !inDoubleQuote
			}
			result.WriteByte(character)
		case '?':
			if inSingleQuote || inDoubleQuote {
				result.WriteByte(character)
				continue
			}
			result.WriteByte('$')
			result.WriteString(strconv.Itoa(argument))
			argument++
		default:
			result.WriteByte(character)
		}
	}
	return result.String()
}
