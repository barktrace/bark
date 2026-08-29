package auth

import (
	"context"
	"net/http"
)

type principalKey struct{}

func (s *Service) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, err := s.Authenticate(r)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"type":"unauthenticated","message":"authentication required"}}`))
			return
		}
		ctx := context.WithValue(r.Context(), principalKey{}, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func PrincipalFromContext(ctx context.Context) (*Principal, bool) {
	principal, ok := ctx.Value(principalKey{}).(*Principal)
	return principal, ok
}

// WithPrincipal attaches an already authenticated principal to a context.
// It is useful for composing Barktrace handlers without duplicating auth state.
func WithPrincipal(ctx context.Context, principal *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, principal)
}

func (p Principal) Membership(organizationID string) (Membership, bool) {
	for _, membership := range p.Memberships {
		if membership.OrganizationID == organizationID {
			return membership, true
		}
	}
	return Membership{}, false
}
