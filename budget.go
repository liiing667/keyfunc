package keyfunc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/MicahParks/jwkset"
)

var (
	// ErrBudgetExceeded is returned when a remote JWK Set exceeds the resource budget. When this error occurs during
	// a refresh, the previously cached set of keys is left untouched.
	ErrBudgetExceeded = errors.New("remote JWK Set resource budget exceeded")
)

// Budget is a unified resource budget for a remote JWK Set. All dimensions are enforced together for every refresh:
// the HTTP response body size, the number of keys in the set, and the marshaled size of each individual key. A
// refresh that exceeds any dimension fails as a whole and does not modify the previously cached keys.
//
// A non-positive value disables that dimension's limit.
type Budget struct {
	// MaxResponseBytes is the maximum number of bytes a remote JWK Set HTTP response body may contain.
	MaxResponseBytes int64
	// MaxKeys is the maximum number of keys a remote JWK Set may contain.
	MaxKeys int
	// MaxKeyBytes is the maximum number of bytes a single marshaled key, including all of its fields, may contain.
	MaxKeyBytes int
}

// DefaultBudget returns the default resource budget applied to remote JWK Set refreshes. It is generous enough for
// typical JWK Sets, such as the ones published by major identity providers, while preventing a malicious or
// malfunctioning remote HTTP resource from exhausting memory.
func DefaultBudget() Budget {
	return Budget{
		MaxResponseBytes: 1 << 20,        // 1 MiB.
		MaxKeys:          128,            // 128 keys.
		MaxKeyBytes:      32 * (1 << 10), // 32 KiB per key.
	}
}

// check validates a full replacement key set against the budget. It must be called before any storage state is
// mutated so that a rejected set leaves the previously cached keys untouched.
func (b Budget) check(keys []jwkset.JWK) error {
	if b.MaxKeys > 0 && len(keys) > b.MaxKeys {
		return fmt.Errorf("%w: key count %d exceeds limit of %d", ErrBudgetExceeded, len(keys), b.MaxKeys)
	}
	if b.MaxKeyBytes > 0 {
		for _, key := range keys {
			marshal := key.Marshal()
			raw, err := json.Marshal(marshal)
			if err != nil {
				return fmt.Errorf("failed to marshal JWK with kid %q for budget check: %w", marshal.KID, err)
			}
			if len(raw) > b.MaxKeyBytes {
				return fmt.Errorf("%w: key with kid %q marshals to %d bytes, exceeding limit of %d", ErrBudgetExceeded, marshal.KID, len(raw), b.MaxKeyBytes)
			}
		}
	}
	return nil
}

// budgetStorage wraps a jwkset.Storage and rejects key sets that exceed the budget before any state changes, so a
// failed refresh leaves the previously cached keys in place.
type budgetStorage struct {
	jwkset.Storage
	budget Budget
}

func (s budgetStorage) KeyReplaceAll(ctx context.Context, given []jwkset.JWK) error {
	if err := s.budget.check(given); err != nil {
		return err
	}
	return s.Storage.KeyReplaceAll(ctx, given)
}

func (s budgetStorage) KeyWrite(ctx context.Context, jwk jwkset.JWK) error {
	if err := s.budget.check([]jwkset.JWK{jwk}); err != nil {
		return err
	}
	return s.Storage.KeyWrite(ctx, jwk)
}

// budgetHTTPClient wraps the given client's transport so that response bodies respect the budget's
// MaxResponseBytes limit. If base is nil, a new client wrapping http.DefaultTransport is created.
func budgetHTTPClient(base *http.Client, budget Budget) *http.Client {
	client := &http.Client{}
	if base != nil {
		c := *base
		client = &c
	}
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	client.Transport = budgetTransport{
		base: transport,
		max:  budget.MaxResponseBytes,
	}
	return client
}

// budgetTransport limits the number of bytes that may be read from an HTTP response body.
type budgetTransport struct {
	base http.RoundTripper
	max  int64
}

func (t budgetTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil || resp.Body == nil || t.max <= 0 {
		return resp, err
	}
	if resp.ContentLength > t.max {
		resp.Body.Close()
		return nil, fmt.Errorf("%w: response body of %d bytes exceeds limit of %d", ErrBudgetExceeded, resp.ContentLength, t.max)
	}
	resp.Body = &budgetBody{
		body:      resp.Body,
		remaining: t.max,
	}
	return resp, nil
}

// budgetBody is an io.ReadCloser that fails with ErrBudgetExceeded once more than the budgeted number of bytes
// would be read.
type budgetBody struct {
	body      io.ReadCloser
	remaining int64
}

func (b *budgetBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		var probe [1]byte
		n, err := b.body.Read(probe[:])
		if n > 0 {
			return 0, fmt.Errorf("%w: response body exceeds byte limit", ErrBudgetExceeded)
		}
		return 0, err
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.body.Read(p)
	b.remaining -= int64(n)
	return n, err
}

func (b *budgetBody) Close() error {
	return b.body.Close()
}
