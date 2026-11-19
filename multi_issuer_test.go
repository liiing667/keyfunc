package keyfunc

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"

	"github.com/MicahParks/jwkset"
)

// Fixed multi-issuer fixture: two issuers share one JWKS endpoint, issuer B is also reachable at its own
// endpoint, and two tenants have explicit boundaries.
const (
	fixtureIssuerA   = "https://issuer-a.example.com"
	fixtureIssuerB   = "https://issuer-b.example.com"
	fixtureSharedURI = "https://keys.example.com/jwks.json"
	fixtureBURI      = "https://issuer-b.example.com/jwks.json"

	fixtureTenant1 = "tenant-1"
	fixtureTenant2 = "tenant-2"
)

var (
	fixtureSeedA = []byte("0123456789abcdef0123456789abcdef")
	fixtureSeedB = []byte("fedcba9876543210fedcba9876543210")
)

func fixtureKey(t *testing.T, seed []byte, kid string) jwkset.JWK {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(seed)
	jwk, err := jwkset.NewJWKFromKey(priv, jwkset.JWKOptions{
		Metadata: jwkset.JWKMetadataOptions{
			KID: kid,
			USE: jwkset.UseSig,
		},
	})
	if err != nil {
		t.Fatalf("Failed to create JWK. Error: %s", err)
	}
	return jwk
}

// fixtureBody returns the JWK Set JSON document an issuer's endpoint would serve, its response identity, and the
// parsed storage.
func fixtureBody(t *testing.T, jwks ...jwkset.JWK) (body []byte, identity string, storage jwkset.Storage) {
	t.Helper()
	marshal := jwkset.JWKSMarshal{}
	for _, jwk := range jwks {
		marshal.Keys = append(marshal.Keys, jwk.Marshal())
	}
	body, err := json.Marshal(marshal)
	if err != nil {
		t.Fatalf("Failed to marshal JWK Set JSON. Error: %s", err)
	}
	var parsed jwkset.JWKSMarshal
	if err = json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal JWK Set JSON. Error: %s", err)
	}
	storage, err = parsed.ToStorage()
	if err != nil {
		t.Fatalf("Failed to create storage from JWK Set JSON. Error: %s", err)
	}
	return body, ResponseIdentity(body, ""), storage
}

func fixtureCache() *MultiIssuerCache {
	return NewMultiIssuerCache(
		TenantBoundary{
			Tenant:  fixtureTenant1,
			Issuers: []string{fixtureIssuerA, fixtureIssuerB},
			URIs:    []string{fixtureSharedURI},
		},
		TenantBoundary{
			Tenant:  fixtureTenant2,
			Issuers: []string{fixtureIssuerB},
			URIs:    []string{fixtureBURI},
		},
	)
}

func TestMultiIssuerCacheHit(t *testing.T) {
	ctx := context.Background()
	cache := fixtureCache()

	_, identityA, storageA := fixtureBody(t, fixtureKey(t, fixtureSeedA, "key-a"))
	key := IssuerCacheKey{
		Tenant:           fixtureTenant1,
		Issuer:           fixtureIssuerA,
		URI:              fixtureSharedURI,
		ResponseIdentity: identityA,
	}
	if err := cache.Store(ctx, key, storageA); err != nil {
		t.Fatalf("Failed to store issuer A entry. Error: %s", err)
	}

	got, err := cache.Load(ctx, key)
	if err != nil {
		t.Fatalf("Expected cache hit for issuer A entry. Error: %s", err)
	}
	jwk, err := got.KeyRead(ctx, "key-a")
	if err != nil {
		t.Fatalf("Failed to read key-a from cached storage. Error: %s", err)
	}
	if jwk.Marshal().KID != "key-a" {
		t.Fatalf("Expected cached KID %q, got %q.", "key-a", jwk.Marshal().KID)
	}

	// Storing the same response identity again is idempotent.
	if err = cache.Store(ctx, key, storageA); err != nil {
		t.Fatalf("Expected idempotent store for same response identity. Error: %s", err)
	}
}

func TestMultiIssuerCacheMismatch(t *testing.T) {
	ctx := context.Background()
	cache := fixtureCache()

	_, identityA, storageA := fixtureBody(t, fixtureKey(t, fixtureSeedA, "key-a"))
	_, identityB, storageB := fixtureBody(t, fixtureKey(t, fixtureSeedB, "key-b"))

	keyA := IssuerCacheKey{Tenant: fixtureTenant1, Issuer: fixtureIssuerA, URI: fixtureSharedURI, ResponseIdentity: identityA}
	if err := cache.Store(ctx, keyA, storageA); err != nil {
		t.Fatalf("Failed to store issuer A entry. Error: %s", err)
	}

	// Same tenant, issuer, and URI, but a different response identity: miss.
	wrongIdentity := keyA
	wrongIdentity.ResponseIdentity = identityB
	if _, err := cache.Load(ctx, wrongIdentity); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("Expected ErrCacheMiss for wrong response identity, got %v.", err)
	}

	// Issuer B shares the endpoint but has no entry yet: miss, not issuer A's keys.
	keyB := IssuerCacheKey{Tenant: fixtureTenant1, Issuer: fixtureIssuerB, URI: fixtureSharedURI, ResponseIdentity: identityB}
	if _, err := cache.Load(ctx, keyB); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("Expected ErrCacheMiss for issuer B on shared endpoint, got %v.", err)
	}

	// Tenant 2's boundary does not allow issuer A or the shared endpoint: fail closed.
	crossTenant := IssuerCacheKey{Tenant: fixtureTenant2, Issuer: fixtureIssuerA, URI: fixtureSharedURI, ResponseIdentity: identityA}
	if _, err := cache.Load(ctx, crossTenant); !errors.Is(err, ErrCacheBoundary) {
		t.Fatalf("Expected ErrCacheBoundary for cross-tenant load, got %v.", err)
	}
	if err := cache.Store(ctx, crossTenant, storageA); !errors.Is(err, ErrCacheBoundary) {
		t.Fatalf("Expected ErrCacheBoundary for cross-tenant store, got %v.", err)
	}

	// Issuer B at its own endpoint is outside tenant 1's boundary: fail closed.
	outsideBoundary := IssuerCacheKey{Tenant: fixtureTenant1, Issuer: fixtureIssuerB, URI: fixtureBURI, ResponseIdentity: identityB}
	if _, err := cache.Load(ctx, outsideBoundary); !errors.Is(err, ErrCacheBoundary) {
		t.Fatalf("Expected ErrCacheBoundary for URI outside boundary, got %v.", err)
	}

	// Tenant 2 can use issuer B at its own endpoint.
	tenant2Key := IssuerCacheKey{Tenant: fixtureTenant2, Issuer: fixtureIssuerB, URI: fixtureBURI, ResponseIdentity: identityB}
	if err := cache.Store(ctx, tenant2Key, storageB); err != nil {
		t.Fatalf("Failed to store tenant 2 entry. Error: %s", err)
	}
	if _, err := cache.Load(ctx, tenant2Key); err != nil {
		t.Fatalf("Expected cache hit for tenant 2 entry. Error: %s", err)
	}
}

func TestMultiIssuerCacheConflictFailsClosed(t *testing.T) {
	ctx := context.Background()
	cache := fixtureCache()

	_, identityA, storageA := fixtureBody(t, fixtureKey(t, fixtureSeedA, "key-a"))
	_, identityB, storageB := fixtureBody(t, fixtureKey(t, fixtureSeedB, "key-b"))

	keyA := IssuerCacheKey{Tenant: fixtureTenant1, Issuer: fixtureIssuerA, URI: fixtureSharedURI, ResponseIdentity: identityA}
	if err := cache.Store(ctx, keyA, storageA); err != nil {
		t.Fatalf("Failed to store issuer A entry. Error: %s", err)
	}

	// A different response identity for the occupied slot conflicts and fails closed.
	conflicting := keyA
	conflicting.ResponseIdentity = identityB
	if err := cache.Store(ctx, conflicting, storageB); !errors.Is(err, ErrCacheConflict) {
		t.Fatalf("Expected ErrCacheConflict for conflicting store, got %v.", err)
	}

	// The original entry is untouched.
	got, err := cache.Load(ctx, keyA)
	if err != nil {
		t.Fatalf("Expected original entry to survive conflict. Error: %s", err)
	}
	if _, err = got.KeyRead(ctx, "key-a"); err != nil {
		t.Fatalf("Expected original key-a to survive conflict. Error: %s", err)
	}
	if _, err = cache.Load(ctx, conflicting); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("Expected conflicting identity to remain uncached, got %v.", err)
	}
}

func TestMultiIssuerCacheRefresh(t *testing.T) {
	ctx := context.Background()
	cache := fixtureCache()

	_, identityA, storageA := fixtureBody(t, fixtureKey(t, fixtureSeedA, "key-a"))
	keyA := IssuerCacheKey{Tenant: fixtureTenant1, Issuer: fixtureIssuerA, URI: fixtureSharedURI, ResponseIdentity: identityA}
	if err := cache.Store(ctx, keyA, storageA); err != nil {
		t.Fatalf("Failed to store issuer A entry. Error: %s", err)
	}

	// Issuer A rotates its keys: the endpoint now serves a new document with a new response identity.
	_, identityA2, storageA2 := fixtureBody(t,
		fixtureKey(t, fixtureSeedA, "key-a"),
		fixtureKey(t, fixtureSeedB, "key-a-rotated"),
	)
	if identityA2 == identityA {
		t.Fatalf("Expected rotated JWK Set to have a different response identity.")
	}
	refreshed := keyA
	refreshed.ResponseIdentity = identityA2
	if err := cache.Refresh(ctx, refreshed, storageA2); err != nil {
		t.Fatalf("Failed to refresh issuer A entry. Error: %s", err)
	}

	got, err := cache.Load(ctx, refreshed)
	if err != nil {
		t.Fatalf("Expected cache hit for refreshed entry. Error: %s", err)
	}
	if _, err = got.KeyRead(ctx, "key-a-rotated"); err != nil {
		t.Fatalf("Expected rotated key in refreshed entry. Error: %s", err)
	}

	// The stale response identity no longer hits.
	if _, err = cache.Load(ctx, keyA); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("Expected ErrCacheMiss for stale response identity, got %v.", err)
	}

	// Refresh still respects tenant boundaries.
	outsideBoundary := IssuerCacheKey{Tenant: fixtureTenant2, Issuer: fixtureIssuerA, URI: fixtureSharedURI, ResponseIdentity: identityA2}
	if err = cache.Refresh(ctx, outsideBoundary, storageA2); !errors.Is(err, ErrCacheBoundary) {
		t.Fatalf("Expected ErrCacheBoundary for refresh outside boundary, got %v.", err)
	}
}

func TestMultiIssuerCacheSharedEndpoint(t *testing.T) {
	ctx := context.Background()
	cache := fixtureCache()

	_, identityA, storageA := fixtureBody(t, fixtureKey(t, fixtureSeedA, "key-a"))
	_, identityB, storageB := fixtureBody(t, fixtureKey(t, fixtureSeedB, "key-b"))

	// Both issuers are explicitly allowed at the shared endpoint within tenant 1's boundary.
	keyA := IssuerCacheKey{Tenant: fixtureTenant1, Issuer: fixtureIssuerA, URI: fixtureSharedURI, ResponseIdentity: identityA}
	keyB := IssuerCacheKey{Tenant: fixtureTenant1, Issuer: fixtureIssuerB, URI: fixtureSharedURI, ResponseIdentity: identityB}
	if err := cache.Store(ctx, keyA, storageA); err != nil {
		t.Fatalf("Failed to store issuer A entry. Error: %s", err)
	}
	if err := cache.Store(ctx, keyB, storageB); err != nil {
		t.Fatalf("Failed to store issuer B entry. Error: %s", err)
	}

	gotA, err := cache.Load(ctx, keyA)
	if err != nil {
		t.Fatalf("Expected cache hit for issuer A. Error: %s", err)
	}
	gotB, err := cache.Load(ctx, keyB)
	if err != nil {
		t.Fatalf("Expected cache hit for issuer B. Error: %s", err)
	}

	// Each issuer gets exactly its own keys despite the shared endpoint.
	if _, err = gotA.KeyRead(ctx, "key-a"); err != nil {
		t.Fatalf("Expected key-a in issuer A entry. Error: %s", err)
	}
	if _, err = gotA.KeyRead(ctx, "key-b"); !errors.Is(err, jwkset.ErrKeyNotFound) {
		t.Fatalf("Expected issuer A entry to not contain key-b, got %v.", err)
	}
	if _, err = gotB.KeyRead(ctx, "key-b"); err != nil {
		t.Fatalf("Expected key-b in issuer B entry. Error: %s", err)
	}
	if _, err = gotB.KeyRead(ctx, "key-a"); !errors.Is(err, jwkset.ErrKeyNotFound) {
		t.Fatalf("Expected issuer B entry to not contain key-a, got %v.", err)
	}
}
