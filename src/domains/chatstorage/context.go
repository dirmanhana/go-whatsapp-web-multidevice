package chatstorage

import "context"

type userContextKey struct{}

// ContextWithUser stores the authenticated user into the provided context for
// per-request scoping (multi-user mode). Lives here — next to the User entity —
// so transport layers (REST middleware, MCP, websocket) can share it without
// import cycles.
func ContextWithUser(ctx context.Context, user *User) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return context.WithValue(ctx, userContextKey{}, user)
}

// UserFromContext retrieves the authenticated user from the context if present.
func UserFromContext(ctx context.Context) (*User, bool) {
	if ctx == nil {
		return nil, false
	}
	if value := ctx.Value(userContextKey{}); value != nil {
		if user, ok := value.(*User); ok {
			return user, true
		}
	}
	return nil, false
}