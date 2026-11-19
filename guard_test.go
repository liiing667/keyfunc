package keyfunc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/time/rate"
)

// Fixed JWK Set response fixtures. The two "oct" keys sharing kid "shared" are distinct secrets, so which one the
// verifier selects must never depend on their order in the response.
const (
	// fixtureAmbiguousAFirst places the attacker-controlled key first in the response.
	fixtureAmbiguousAFirst = `{"keys":[` +
		`{"kty":"oct","k":"c2VjcmV0LW9uZS0wMDAwMDAwMDAwMDA","kid":"shared","use":"sig","alg":"HS256"},` +
		`{"kty":"oct","k":"c2VjcmV0LXR3by0wMDAwMDAwMDAwMDA","kid":"shared","use":"sig","alg":"HS256"}` +
		`]}`
	// fixtureAmbiguousBFirst reverses the order to prove rejection is order independent.
	fixtureAmbiguousBFirst = `{"keys":[` +
		`{"kty":"oct","k":"c2VjcmV0LXR3by0wMDAwMDAwMDAwMDA","kid":"shared","use":"sig","alg":"HS256"},` +
		`{"kty":"oct","k":"c2VjcmV0LW9uZS0wMDAwMDAwMDAwMDA","kid":"shared","use":"sig","alg":"HS256"}` +
		`]}`
	// fixtureExactDuplicate repeats the same key material twice, which is harmless and must be deduplicated.
	fixtureExactDuplicate = `{"keys":[` +
		`{"kty":"oct","k":"c2VjcmV0LW9uZS0wMDAwMDAwMDAwMDA","kid":"shared","use":"sig","alg":"HS256"},` +
		`{"kty":"oct","k":"c2VjcmV0LW9uZS0wMDAwMDAwMDAwMDA","kid":"shared","use":"sig","alg":"HS256"}` +
		`]}`
	// fixtureDistinctRoles reuses the "shared" kid but gives each key a non-overlapping use and alg.
	fixtureDistinctRoles = `{"keys":[` +
		`{"kty":"oct","k":"c2VjcmV0LW9uZS0wMDAwMDAwMDAwMDA","kid":"shared","use":"sig","alg":"HS256"},` +
		`{"kty":"oct","k":"c2VjcmV0LXR3by0wMDAwMDAwMDAwMDA","kid":"shared","use":"enc","alg":"HS384"}` +
		`]}`
	// fixtureLegalMultipleKID holds distinct keys with distinct kids, the normal rotation-ready case.
	fixtureLegalMultipleKID = `{"keys":[` +
		`{"kty":"oct","k":"c2VjcmV0LW9uZS0wMDAwMDAwMDAwMDA","kid":"key-one","use":"sig","alg":"HS256"},` +
		`{"kty":"oct","k":"c2VjcmV0LXR3by0wMDAwMDAwMDAwMDA","kid":"key-two","use":"sig","alg":"HS256"}` +
		`]}`
	// fixtureSingleKey is the well-formed post-rotation response containing only the new key.
	fixtureSingleKey = `{"keys":[` +
		`{"kty":"oct","k":"c2VjcmV0LXR3by0wMDAwMDAwMDAwMDA","kid":"shared","use":"sig","alg":"HS256"}` +
		`]}`
)

var fixtureSecrets = map[string][]byte{
	"secret-one": []byte("secret-one-000000000000"),
	"secret-two": []byte("secret-two-000000000000"),
}

func fixtureServer(t *testing.T, responses ...string) *httptest.Server {
	t.Helper()
	index := 0
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := responses[index]
		if index < len(responses)-1 {
			index++
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
}

func newFixtureKeyfunc(t *testing.T, url string) (Keyfunc, jwkset.Storage) {
	t.Helper()
	ctx := context.Background()
	cache := jwkset.NewMemoryStorage()
	store, err := newGuardedStorageFromHTTP(url, jwkset.HTTPClientStorageOptions{
		Ctx:                       ctx,
		NoErrorReturnFirstHTTPReq: false,
		Storage:                   cache,
	})
	if err != nil {
		t.Fatalf("Failed to create guarded HTTP storage: %v", err)
	}
	k, err := New(Options{Ctx: ctx, Storage: store})
	if err != nil {
		t.Fatalf("Failed to create keyfunc: %v", err)
	}
	return k, store
}

func signHS256(t *testing.T, kid string, secret []byte) string {
	t.Helper()
	token := jwt.New(jwt.SigningMethodHS256)
	token.Header[jwkset.HeaderKID] = kid
	signed, err := token.SignedString(secret)
	if err != nil {
		t.Fatalf("Failed to sign JWT: %v", err)
	}
	return signed
}

// TestGuardRejectsAmbiguousKID proves an ambiguous set fails closed regardless of response order, and that nothing
// from the rejected response reaches the cache.
func TestGuardRejectsAmbiguousKID(t *testing.T) {
	for _, fixture := range []string{fixtureAmbiguousAFirst, fixtureAmbiguousBFirst} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(fixture))
		}))

		ctx := context.Background()
		cache := jwkset.NewMemoryStorage()
		_, err := newGuardedStorageFromHTTP(server.URL, jwkset.HTTPClientStorageOptions{
			Ctx:                       ctx,
			NoErrorReturnFirstHTTPReq: false,
			Storage:                   cache,
		})
		if !errors.Is(err, ErrAmbiguousKID) {
			t.Fatalf("Expected ErrAmbiguousKID for ambiguous JWKS, got: %v", err)
		}

		snapshot, err := cache.KeyReadAll(ctx)
		if err != nil {
			t.Fatalf("Failed to read cache snapshot: %v", err)
		}
		if len(snapshot) != 0 {
			t.Fatalf("Expected rejected response to leave the cache empty, got %d keys", len(snapshot))
		}

		server.Close()
	}
}

// TestGuardRejectsAmbiguousKIDThroughKeyfunc proves the default keyfunc constructor surfaces the same failure.
func TestGuardRejectsAmbiguousKIDThroughKeyfunc(t *testing.T) {
	server := fixtureServer(t, fixtureAmbiguousAFirst)
	defer server.Close()

	_, err := NewDefaultCtx(context.Background(), []string{server.URL})
	if !errors.Is(err, ErrAmbiguousKID) {
		t.Fatalf("Expected ErrAmbiguousKID through NewDefaultCtx, got: %v", err)
	}

	_, err = NewJWKSetJSON(json.RawMessage(fixtureAmbiguousAFirst))
	if !errors.Is(err, ErrAmbiguousKID) {
		t.Fatalf("Expected ErrAmbiguousKID through NewJWKSetJSON, got: %v", err)
	}
}

// TestGuardSelectsUnambiguousKey proves a single key per identity is selected and verifies the matching token only.
func TestGuardSelectsUnambiguousKey(t *testing.T) {
	server := fixtureServer(t, fixtureSingleKey)
	defer server.Close()

	k, store := newFixtureKeyfunc(t, server.URL)

	snapshot, err := store.KeyReadAll(context.Background())
	if err != nil {
		t.Fatalf("Failed to read cache snapshot: %v", err)
	}
	if len(snapshot) != 1 {
		t.Fatalf("Expected exactly 1 cached key, got %d", len(snapshot))
	}

	good := signHS256(t, "shared", fixtureSecrets["secret-two"])
	if _, err = jwt.Parse(good, k.Keyfunc); err != nil {
		t.Fatalf("Expected token signed by the cached key to verify, got: %v", err)
	}

	bad := signHS256(t, "shared", fixtureSecrets["secret-one"])
	if _, err = jwt.Parse(bad, k.Keyfunc); !errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		t.Fatalf("Expected signature failure with a non-cached secret, got: %v", err)
	}
}

// TestGuardDeduplicatesExactJWK proves a byte-identical repeated JWK is collapsed instead of rejected.
func TestGuardDeduplicatesExactJWK(t *testing.T) {
	server := fixtureServer(t, fixtureExactDuplicate)
	defer server.Close()

	k, store := newFixtureKeyfunc(t, server.URL)

	snapshot, err := store.KeyReadAll(context.Background())
	if err != nil {
		t.Fatalf("Failed to read cache snapshot: %v", err)
	}
	if len(snapshot) != 1 {
		t.Fatalf("Expected exact duplicates to collapse to 1 key, got %d", len(snapshot))
	}

	signed := signHS256(t, "shared", fixtureSecrets["secret-one"])
	if _, err = jwt.Parse(signed, k.Keyfunc); err != nil {
		t.Fatalf("Expected deduplicated key to verify its token, got: %v", err)
	}
}

// TestGuardAllowsDistinctRoles proves same-kid keys with non-overlapping use/alg are both cached, while the verifier
// still picks the sig/HS256 key for a matching token.
func TestGuardAllowsDistinctRoles(t *testing.T) {
	server := fixtureServer(t, fixtureDistinctRoles)
	defer server.Close()

	k, store := newFixtureKeyfunc(t, server.URL)

	snapshot, err := store.KeyReadAll(context.Background())
	if err != nil {
		t.Fatalf("Failed to read cache snapshot: %v", err)
	}
	if len(snapshot) != 2 {
		t.Fatalf("Expected both role-distinct keys cached, got %d", len(snapshot))
	}

	sigToken := signHS256(t, "shared", fixtureSecrets["secret-one"])
	if _, err = jwt.Parse(sigToken, k.Keyfunc); err != nil {
		t.Fatalf("Expected sig/HS256 token to verify, got: %v", err)
	}

	// The enc/HS384 secret must never be selected for a sig/HS256 token.
	encToken := signHS256(t, "shared", fixtureSecrets["secret-two"])
	if _, err = jwt.Parse(encToken, k.Keyfunc); !errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		t.Fatalf("Expected signature failure when only the enc key matches by material, got: %v", err)
	}
}

// TestGuardAllowsLegalMultipleKID proves distinct kids coexist and are independently selectable.
func TestGuardAllowsLegalMultipleKID(t *testing.T) {
	server := fixtureServer(t, fixtureLegalMultipleKID)
	defer server.Close()

	k, store := newFixtureKeyfunc(t, server.URL)

	snapshot, err := store.KeyReadAll(context.Background())
	if err != nil {
		t.Fatalf("Failed to read cache snapshot: %v", err)
	}
	if len(snapshot) != 2 {
		t.Fatalf("Expected 2 distinct kid keys cached, got %d", len(snapshot))
	}

	for kid, secret := range map[string][]byte{
		"key-one": fixtureSecrets["secret-one"],
		"key-two": fixtureSecrets["secret-two"],
	} {
		signed := signHS256(t, kid, secret)
		if _, err = jwt.Parse(signed, k.Keyfunc); err != nil {
			t.Fatalf("Expected token for kid %q to verify, got: %v", kid, err)
		}
	}
}

// TestGuardKeyReplaceAllAtomicity proves the cache operation backing an HTTP refresh is all-or-nothing: an ambiguous
// replacement is rejected while the previously cached good key is retained unchanged.
func TestGuardKeyReplaceAllAtomicity(t *testing.T) {
	ctx := context.Background()
	good := mustJWKSFromFixture(t, fixtureSingleKey)
	ambiguous := mustJWKSFromFixture(t, fixtureAmbiguousAFirst)

	cache := newGuardedStorage(jwkset.NewMemoryStorage())
	if err := cache.KeyReplaceAll(ctx, good); err != nil {
		t.Fatalf("Initial good set should be cached: %v", err)
	}

	err := cache.KeyReplaceAll(ctx, ambiguous)
	if !errors.Is(err, ErrAmbiguousKID) {
		t.Fatalf("Expected ambiguous replacement to be rejected, got: %v", err)
	}

	snapshot, err := cache.KeyReadAll(ctx)
	if err != nil {
		t.Fatalf("Failed to read cache snapshot: %v", err)
	}
	if len(snapshot) != 1 || snapshot[0].Marshal().KID != "shared" ||
		snapshot[0].Marshal().K != "c2VjcmV0LXR3by0wMDAwMDAwMDAwMDA" {
		t.Fatalf("Expected previous good key to be retained, got %+v", snapshot)
	}

	// A well-formed rotation still replaces the cache wholesale.
	rotated := mustJWKSFromFixture(t, fixtureLegalMultipleKID)
	if err = cache.KeyReplaceAll(ctx, rotated); err != nil {
		t.Fatalf("Expected clean rotation to be cached: %v", err)
	}
	snapshot, err = cache.KeyReadAll(ctx)
	if err != nil {
		t.Fatalf("Failed to read cache snapshot: %v", err)
	}
	if len(snapshot) != 2 {
		t.Fatalf("Expected rotated cache to hold 2 keys, got %d", len(snapshot))
	}
}

// TestGuardKeyWriteRejectsAmbiguity proves an individual write is validated against the current cache instead of
// silently shadowing an existing key.
func TestGuardKeyWriteRejectsAmbiguity(t *testing.T) {
	ctx := context.Background()
	good := mustJWKSFromFixture(t, fixtureSingleKey)

	cache := newGuardedStorage(jwkset.NewMemoryStorage())
	if err := cache.KeyReplaceAll(ctx, good); err != nil {
		t.Fatalf("Initial good set should be cached: %v", err)
	}

	conflicting := good[0]
	conflictingMarshal := conflicting.Marshal()
	conflictingMarshal.K = "c2VjcmV0LW9uZS0wMDAwMDAwMDAwMDA"
	conflicting, err := jwkset.NewJWKFromMarshal(conflictingMarshal,
		jwkset.JWKMarshalOptions{Private: true}, jwkset.JWKValidateOptions{})
	if err != nil {
		t.Fatalf("Failed to build conflicting JWK: %v", err)
	}

	err = cache.KeyWrite(ctx, conflicting)
	if !errors.Is(err, ErrAmbiguousKID) {
		t.Fatalf("Expected ambiguous KeyWrite to be rejected, got: %v", err)
	}
	snapshot, err := cache.KeyReadAll(ctx)
	if err != nil {
		t.Fatalf("Failed to read cache snapshot: %v", err)
	}
	if len(snapshot) != 1 {
		t.Fatalf("Expected original key retained after rejected write, got %d keys", len(snapshot))
	}
}

// TestGuardRotationAcrossResponses proves real HTTP refreshes move from one unambiguous set to another without
// tripping the guard, while an ambiguous response is refused at construction.
func TestGuardRotationAcrossResponses(t *testing.T) {
	firstServer := fixtureServer(t, fixtureSingleKey)
	defer firstServer.Close()
	rotatedServer := fixtureServer(t, fixtureLegalMultipleKID)
	defer rotatedServer.Close()

	first, err := NewDefaultCtx(context.Background(), []string{firstServer.URL})
	if err != nil {
		t.Fatalf("First response should be accepted: %v", err)
	}
	if snapshot, err := first.Storage().KeyReadAll(context.Background()); err != nil || len(snapshot) != 1 {
		t.Fatalf("Expected 1 key after first fetch, got %d (err: %v)", len(snapshot), err)
	}

	rotated, err := NewDefaultCtx(context.Background(), []string{rotatedServer.URL})
	if err != nil {
		t.Fatalf("Rotated response should be accepted: %v", err)
	}
	if snapshot, err := rotated.Storage().KeyReadAll(context.Background()); err != nil || len(snapshot) != 2 {
		t.Fatalf("Expected 2 keys after rotation fetch, got %d (err: %v)", len(snapshot), err)
	}
}

// TestGuardUnknownKIDRefreshRejectsAmbiguity drives the jwkset unknown-kid refresh path against a server that turns
// ambiguous after the initial fetch. The rejected refresh must leave the good cached key usable.
func TestGuardUnknownKIDRefreshRejectsAmbiguity(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := fixtureServer(t, fixtureSingleKey, fixtureAmbiguousAFirst, fixtureSingleKey)
	defer server.Close()

	store, err := newGuardedStorageFromHTTP(server.URL, jwkset.HTTPClientStorageOptions{
		Ctx:                       ctx,
		NoErrorReturnFirstHTTPReq: false,
	})
	if err != nil {
		t.Fatalf("Initial guarded storage should be created: %v", err)
	}
	client, err := jwkset.NewHTTPClient(jwkset.HTTPClientOptions{
		HTTPURLs:          map[string]jwkset.Storage{server.URL: store},
		RefreshUnknownKID: rate.NewLimiter(rate.Inf, 1),
	})
	if err != nil {
		t.Fatalf("Failed to create HTTP client: %v", err)
	}
	k, err := New(Options{Ctx: ctx, Storage: client})
	if err != nil {
		t.Fatalf("Failed to create keyfunc: %v", err)
	}

	good := signHS256(t, "shared", fixtureSecrets["secret-two"])
	if _, err = jwt.Parse(good, k.Keyfunc); err != nil {
		t.Fatalf("Expected initially cached key to verify: %v", err)
	}

	// Reading an unknown kid forces a refresh; the second server response is ambiguous and must not poison the cache.
	if _, err = client.KeyRead(ctx, "not-a-real-kid"); !errors.Is(err, jwkset.ErrKeyNotFound) {
		t.Fatalf("Expected ErrKeyNotFound after refresh, got: %v", err)
	}
	if _, err = jwt.Parse(good, k.Keyfunc); err != nil {
		t.Fatalf("Expected cached key retained after ambiguous refresh: %v", err)
	}

	// A third, clean refresh succeeds and the same good key remains verifiable.
	if _, err = client.KeyRead(ctx, "still-not-a-real-kid"); !errors.Is(err, jwkset.ErrKeyNotFound) {
		t.Fatalf("Expected ErrKeyNotFound after clean refresh, got: %v", err)
	}
	if _, err = jwt.Parse(good, k.Keyfunc); err != nil {
		t.Fatalf("Expected cached key to verify after clean refresh: %v", err)
	}
}

func mustJWKSFromFixture(t *testing.T, fixture string) []jwkset.JWK {
	t.Helper()
	var jwks jwkset.JWKSMarshal
	if err := json.Unmarshal([]byte(fixture), &jwks); err != nil {
		t.Fatalf("Failed to unmarshal fixture: %v", err)
	}
	slice, err := jwks.JWKSlice()
	if err != nil {
		t.Fatalf("Failed to build JWK slice from fixture: %v", err)
	}
	return slice
}
