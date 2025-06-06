package common

import (
	"context"
)

// Context keys for request-scoped values
type contextKey struct {
	name string
}

var (
	// ConnIDKey is the context key for connection ID
	ConnIDKey = &contextKey{"conn-id"}

	// UserContextKey is the context key for user context
	UserContextKey = &contextKey{"user"}
)

// WithConnID adds connection ID to context
func WithConnID(ctx context.Context, connID string) context.Context {
	return context.WithValue(ctx, ConnIDKey, connID)
}

// GetConnID retrieves connection ID from context
func GetConnID(ctx context.Context) (string, bool) {
	connID, ok := ctx.Value(ConnIDKey).(string)
	return connID, ok
}

// WithUserContext adds user context to context
func WithUserContext(ctx context.Context, userCtx *UserContext) context.Context {
	return context.WithValue(ctx, UserContextKey, userCtx)
}

// GetUserContext retrieves user context from context
func GetUserContext(ctx context.Context) (*UserContext, bool) {
	userCtx, ok := ctx.Value(UserContextKey).(*UserContext)
	return userCtx, ok
}
