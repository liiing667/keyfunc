package keyfunc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/MicahParks/jwkset"
)

var (
	// ErrCacheBoundary is returned when a tenant's explicit boundary does not allow the requested issuer and URI
	// pair. The cache fails closed: the entry is neither read nor written.
	ErrCacheBoundary = errors.New("tenant boundary does not allow the issuer and URI pair")
	// ErrCacheConflict is returned when a cache slot is already occupied by an entry with a different response
	// identity. The cache fails closed: the existing entry is left untouched. Use Refresh to replace an entry
	// after re-fetching the remote JWK Set.
	ErrCacheConflict = errors.New("cache slot occupied by a different response identity")
	// ErrCacheMiss is returned when no entry matches the full issuer cache key.
	ErrCacheMiss = errors.New("no cache entry for the issuer cache key")
)

// IssuerCacheKey identifies a cached JWK Set. All four dimensions must match for a cache hit: the issuer, the
// endpoint URI, the identity of the HTTP response the JWK Set was parsed from, and the tenant boundary. This
// prevents issuers or tenants that share an endpoint from silently sharing each other's keys.
type IssuerCacheKey struct {
	// Tenant is the tenant boundary the cache entry belongs to.
	Tenant string
	// Issuer is the "iss" value the cached keys are trusted for.
	Issuer string
	// URI is the remote JWK Set endpoint the keys were fetched from.
	URI string
	// ResponseIdentity identifies the HTTP response the JWK Set was parsed from. See ResponseIdentity.
	ResponseIdentity string
}

// slot is the response-identity-independent portion of an IssuerCacheKey. One slot holds at most one entry.
type slot struct {
	tenant string
	issuer string
	uri    string
}

func (k IssuerCacheKey) slot() slot {
	return slot{
		tenant: k.Tenant,
		issuer: k.Issuer,
		uri:    k.URI,
	}
}

// TenantBoundary explicitly declares which issuer and endpoint URI pairs a tenant may use. Sharing an endpoint
// between issuers or tenants only works when a boundary explicitly allows it.
type TenantBoundary struct {
	// Tenant is the tenant this boundary applies to.
	Tenant string
	// Issuers are the issuer ("iss") values the tenant trusts.
	Issuers []string
	// URIs are the remote JWK Set endpoints the tenant may use.
	URIs []string
}

func (b TenantBoundary) allows(issuer, uri string) bool {
	return slices.Contains(b.Issuers, issuer) && slices.Contains(b.URIs, uri)
}

// MultiIssuerCache caches JWK Set storage per issuer, endpoint URI, response identity, and tenant boundary. It is
// safe for concurrent use.
type MultiIssuerCache struct {
	mu         sync.RWMutex
	boundaries map[string]TenantBoundary
	entries    map[slot]jwkset.Storage
	identities map[slot]string
}

// NewMultiIssuerCache creates a new MultiIssuerCache with the given explicit tenant boundaries.
func NewMultiIssuerCache(boundaries ...TenantBoundary) *MultiIssuerCache {
	b := make(map[string]TenantBoundary, len(boundaries))
	for _, boundary := range boundaries {
		b[boundary.Tenant] = boundary
	}
	return &MultiIssuerCache{
		boundaries: b,
		entries:    make(map[slot]jwkset.Storage),
		identities: make(map[slot]string),
	}
}

// ResponseIdentity computes a stable identity for a JWK Set HTTP response. The ETag is used when present,
// otherwise the SHA-256 of the response body. Responses with different key material always produce different
// identities, so a changed or attacker-swapped JWK Set cannot occupy another response's cache entry.
func ResponseIdentity(body []byte, etag string) string {
	if etag != "" {
		return "etag:" + etag
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Load returns the cached storage for the exact key. It fails closed with ErrCacheBoundary when the tenant's
// boundary does not allow the issuer and URI pair, and with ErrCacheMiss when no entry matches all four key
// dimensions.
func (c *MultiIssuerCache) Load(_ context.Context, key IssuerCacheKey) (jwkset.Storage, error) {
	if err := c.checkBoundary(key); err != nil {
		return nil, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	s := key.slot()
	identity, ok := c.identities[s]
	if !ok || identity != key.ResponseIdentity {
		return nil, fmt.Errorf("%w: tenant %q issuer %q URI %q", ErrCacheMiss, key.Tenant, key.Issuer, key.URI)
	}
	return c.entries[s], nil
}

// Store writes storage to the key's slot. It fails closed with ErrCacheBoundary when the tenant's boundary does
// not allow the issuer and URI pair. If the slot is already occupied by a different response identity, it fails
// closed with ErrCacheConflict and leaves the existing entry untouched. Storing the same response identity again
// is idempotent.
func (c *MultiIssuerCache) Store(_ context.Context, key IssuerCacheKey, storage jwkset.Storage) error {
	if err := c.checkBoundary(key); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s := key.slot()
	if identity, ok := c.identities[s]; ok && identity != key.ResponseIdentity {
		return fmt.Errorf("%w: tenant %q issuer %q URI %q", ErrCacheConflict, key.Tenant, key.Issuer, key.URI)
	}
	c.entries[s] = storage
	c.identities[s] = key.ResponseIdentity
	return nil
}

// Refresh replaces the key's slot after the remote JWK Set has been re-fetched, allowing the response identity to
// change. It fails closed with ErrCacheBoundary when the tenant's boundary does not allow the issuer and URI
// pair.
func (c *MultiIssuerCache) Refresh(_ context.Context, key IssuerCacheKey, storage jwkset.Storage) error {
	if err := c.checkBoundary(key); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s := key.slot()
	c.entries[s] = storage
	c.identities[s] = key.ResponseIdentity
	return nil
}

func (c *MultiIssuerCache) checkBoundary(key IssuerCacheKey) error {
	boundary, ok := c.boundaries[key.Tenant]
	if !ok || !boundary.allows(key.Issuer, key.URI) {
		return fmt.Errorf("%w: tenant %q issuer %q URI %q", ErrCacheBoundary, key.Tenant, key.Issuer, key.URI)
	}
	return nil
}
