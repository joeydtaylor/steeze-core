package auth

type contextKey struct{ name string }

var userCtxKey = &contextKey{"user"}
