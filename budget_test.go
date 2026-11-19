package keyfunc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// budgetTestRSAKey is a fixed RSA public JWK. The fixed budgetTestJWT below is signed for this key.
	budgetTestRSAKey = `{"kty":"RSA","e":"AQAB","kid":"ee8d626d","n":"gRda5b0pkgTytDuLrRnNSYhvfMIyM0ASq2ZggY4dVe12JV8N7lyXilyqLKleD-2lziivvzE8O8CdIC2vUf0tBD7VuMyldnZruSEZWCuKJPdgKgy9yPpShmD2NyhbwQIAbievGMJIp_JMwz8MkdY5pzhPECGNgCEtUAmsrrctP5V8HuxaxGt9bb-DdPXkYWXW3MPMSlVpGZ5GiIeTABxqYNG2MSoYeQ9x8O3y488jbassTqxExI_4w9MBQBJR9HIXjWrrrenCcDlMY71rzkbdj3mmcn9xMq2vB5OhfHyHTihbUPLSm83aFWSuW9lE7ogMc93XnrB8evIAk6VfsYlS9Q"}`
	// budgetTestECKey is a fixed ECDSA public JWK.
	budgetTestECKey = `{"kty":"EC","crv":"P-256","kid":"711d48d1","x":"tfXCoBU-wXemeQCkME1gMZWK0-UECCHIkedASZR0t-Q","y":"9xzYtnKQdiQJHCtGwpZWF21eP1fy5x4wC822rCilmBw"}`
	// budgetTestJWT is a fixed RS256 JWT for the key in budgetTestRSAKey.
	budgetTestJWT = "eyJraWQiOiJlZThkNjI2ZCIsInR5cCI6IkpXVCIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJXZWlkb25nIiwiYXVkIjoiVGFzaHVhbiIsImlzcyI6Imp3a3Mtc2VydmljZS5hcHBzcG90LmNvbSIsImlhdCI6MTYzMTM2OTk1NSwianRpIjoiNDY2M2E5MTAtZWU2MC00NzcwLTgxNjktY2I3NDdiMDljZjU0In0.LwD65d5h6U_2Xco81EClMa_1WIW4xXZl8o4b7WzY_7OgPD2tNlByxvGDzP7bKYA9Gj--1mi4Q4li4CAnKJkaHRYB17baC0H5P9lKMPuA6AnChTzLafY6yf-YadA7DmakCtIl7FNcFQQL2DXmh6gS9J6TluFoCIXj83MqETbDWpL28o3XAD_05UP8VLQzH2XzyqWKi97mOuvz-GsDp9mhBYQUgN3csNXt2v2l-bUPWe19SftNej0cxddyGu06tXUtaS6K0oe0TTbaqc3hmfEiu5G0J8U6ztTUMwXkBvaknE640NPgMQJqBaey0E4u0txYgyvMvvxfwtcOrDRYqYPBnA"
)

var (
	// budgetTestSmallSet is a fixed, normal-sized two-key JWK Set.
	budgetTestSmallSet = `{"keys":[` + budgetTestRSAKey + `,` + budgetTestECKey + `]}`
	// budgetTestBigKeySet is a fixed JWK Set containing a single key with an oversized "kid" field.
	budgetTestBigKeySet = `{"keys":[{"kty":"RSA","e":"AQAB","kid":"` + strings.Repeat("a", 8192) + `","n":"gRda5b0pkgTytDuLrRnNSYhvfMIyM0ASq2ZggY4dVe12JV8N7lyXilyqLKleD-2lziivvzE8O8CdIC2vUf0tBD7VuMyldnZruSEZWCuKJPdgKgy9yPpShmD2NyhbwQIAbievGMJIp_JMwz8MkdY5pzhPECGNgCEtUAmsrrctP5V8HuxaxGt9bb-DdPXkYWXW3MPMSlVpGZ5GiIeTABxqYNG2MSoYeQ9x8O3y488jbassTqxExI_4w9MBQBJR9HIXjWrrrenCcDlMY71rzkbdj3mmcn9xMq2vB5OhfHyHTihbUPLSm83aFWSuW9lE7ogMc93XnrB8evIAk6VfsYlS9Q"}]}`
)

// budgetServer serves a fixed JWK Set response that can be swapped between refreshes.
type budgetServer struct {
	*httptest.Server
	mux      sync.RWMutex
	response string
}

func newBudgetServer(t *testing.T, response string) *budgetServer {
	t.Helper()
	b := &budgetServer{response: response}
	b.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mux.RLock()
		defer b.mux.RUnlock()
		_, _ = w.Write([]byte(b.response))
	}))
	t.Cleanup(b.Server.Close)
	return b
}

func (b *budgetServer) setResponse(response string) {
	b.mux.Lock()
	defer b.mux.Unlock()
	b.response = response
}

// budgetErrs collects refresh errors from the refresh goroutine.
type budgetErrs struct {
	mux  sync.Mutex
	errs []error
}

func (b *budgetErrs) handler(_ string) func(ctx context.Context, err error) {
	return func(_ context.Context, err error) {
		b.mux.Lock()
		defer b.mux.Unlock()
		b.errs = append(b.errs, err)
	}
}

func (b *budgetErrs) waitFor(t *testing.T, target error) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		b.mux.Lock()
		for _, err := range b.errs {
			if errors.Is(err, target) {
				b.mux.Unlock()
				return
			}
		}
		b.mux.Unlock()
		if time.Now().After(deadline) {
			t.Fatalf("Timed out waiting for refresh error %v.", target)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestRefreshBudgetMatrix is a fixed offline response matrix. Each row serves a fixed JWK Set response under a
// fixed budget and asserts whether the set is accepted (compatibility) or rejected with ErrBudgetExceeded
// (resource refusal) without modifying the cached keys.
func TestRefreshBudgetMatrix(t *testing.T) {
	defaultBudget := DefaultBudget()
	byteBudget := Budget{MaxResponseBytes: 256, MaxKeys: 128, MaxKeyBytes: 32 * (1 << 10)}
	keyCountBudget := Budget{MaxResponseBytes: 1 << 20, MaxKeys: 1, MaxKeyBytes: 32 * (1 << 10)}
	keyFieldBudget := Budget{MaxResponseBytes: 1 << 20, MaxKeys: 128, MaxKeyBytes: 1024}

	tc := map[string]struct {
		response string
		budget   Budget
		wantErr  bool
		wantKeys int
	}{
		"Small set within default budget": {
			response: budgetTestSmallSet,
			budget:   defaultBudget,
			wantKeys: 2,
		},
		"Response body exceeds byte budget": {
			response: budgetTestSmallSet,
			budget:   byteBudget,
			wantErr:  true,
		},
		"Key count exceeds budget": {
			response: budgetTestSmallSet,
			budget:   keyCountBudget,
			wantErr:  true,
		},
		"Single key field exceeds budget": {
			response: budgetTestBigKeySet,
			budget:   keyFieldBudget,
			wantErr:  true,
		},
	}
	for name, tt := range tc {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			server := newBudgetServer(t, tt.response)
			errs := &budgetErrs{}
			budget := tt.budget
			k, err := NewDefaultOverrideCtx(ctx, []string{server.URL}, Override{
				RefreshBudget:           &budget,
				RefreshErrorHandlerFunc: errs.handler,
			})
			if err != nil {
				t.Fatalf("Failed to create keyfunc. Error: %s", err)
			}

			keys, err := k.Storage().KeyReadAll(ctx)
			if err != nil {
				t.Fatalf("Failed to read all keys from storage. Error: %s", err)
			}
			if tt.wantErr {
				errs.waitFor(t, ErrBudgetExceeded)
				if len(keys) != 0 {
					t.Fatalf("Expected no keys to be cached after budget rejection, but got %d.", len(keys))
				}
				return
			}
			if len(keys) != tt.wantKeys {
				t.Fatalf("Expected %d keys to be cached, but got %d.", tt.wantKeys, len(keys))
			}

			// Compatibility: a JWT signed for a key in the accepted set still verifies.
			token, err := jwt.Parse(budgetTestJWT, k.Keyfunc)
			if err != nil {
				t.Fatalf("Failed to parse JWT. Error: %s", err)
			}
			if !token.Valid {
				t.Fatal("Expected token to be valid.")
			}
		})
	}
}

// TestRefreshBudgetKeepsPreviousKeys verifies that a refresh exceeding the budget, in any dimension, leaves the
// previously cached key set in place and usable.
func TestRefreshBudgetKeepsPreviousKeys(t *testing.T) {
	budget := Budget{MaxResponseBytes: 1 << 20, MaxKeys: 2, MaxKeyBytes: 1024}

	tc := map[string]string{
		"Oversized response body": strings.Repeat(" ", 2<<20) + budgetTestSmallSet,
		"Too many keys":           `{"keys":[` + budgetTestRSAKey + `,` + budgetTestECKey + `,` + budgetTestECKey + `]}`,
		"Oversized single key":    budgetTestBigKeySet,
	}
	for name, badResponse := range tc {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			server := newBudgetServer(t, budgetTestSmallSet)
			errs := &budgetErrs{}
			b := budget
			k, err := NewDefaultOverrideCtx(ctx, []string{server.URL}, Override{
				RefreshBudget:           &b,
				RefreshErrorHandlerFunc: errs.handler,
				RefreshInterval:         10 * time.Millisecond,
			})
			if err != nil {
				t.Fatalf("Failed to create keyfunc. Error: %s", err)
			}

			token, err := jwt.Parse(budgetTestJWT, k.Keyfunc)
			if err != nil {
				t.Fatalf("Failed to parse JWT before refresh. Error: %s", err)
			}
			if !token.Valid {
				t.Fatal("Expected token to be valid before refresh.")
			}

			server.setResponse(badResponse)
			errs.waitFor(t, ErrBudgetExceeded)

			keys, err := k.Storage().KeyReadAll(ctx)
			if err != nil {
				t.Fatalf("Failed to read all keys from storage. Error: %s", err)
			}
			if len(keys) != 2 {
				t.Fatalf("Expected the 2 previously cached keys to remain after budget rejection, but got %d.", len(keys))
			}
			token, err = jwt.Parse(budgetTestJWT, k.Keyfunc)
			if err != nil {
				t.Fatalf("Failed to parse JWT after rejected refresh. Error: %s", err)
			}
			if !token.Valid {
				t.Fatal("Expected token to be valid after rejected refresh.")
			}
		})
	}
}
