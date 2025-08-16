package auth

import "context"

func (m *Middleware) GetUser(ctx context.Context) User {
	if user, ok := ctx.Value(userCtxKey).(User); ok {
		return user
	}
	return User{}
}

func (m *Middleware) IsRole(ctx context.Context, role Role) bool {
	if u, ok := ctx.Value(userCtxKey).(User); ok {
		return u.Role.Name == role.Name || (m.adminRole != "" && u.Role.Name == m.adminRole)
	}
	return false
}

func (m *Middleware) IsAdmin(ctx context.Context) bool {
	if u, ok := ctx.Value(userCtxKey).(User); ok && m.adminRole != "" {
		return u.Role.Name == m.adminRole
	}
	return false
}

func (m *Middleware) IsUser(ctx context.Context, username string) bool {
	if u, ok := ctx.Value(userCtxKey).(User); ok {
		return u.Username == username || (m.adminRole != "" && u.Role.Name == m.adminRole)
	}
	return false
}

func (m *Middleware) IsAuthenticated(ctx context.Context) bool {
	u, ok := ctx.Value(userCtxKey).(User)
	return ok && u.Username != ""
}
