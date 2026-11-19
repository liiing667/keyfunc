package keyfunc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/MicahParks/jwkset"
)

var (
	// ErrAmbiguousKID is returned when a JWK Set contains multiple keys sharing the same key ID ("kid") that are not
	// unambiguously distinguishable by their intended use ("use") and algorithm ("alg"). Failing closed here prevents a
	// remote JWK Set from making the verifier select a different public key than the one an auditor would observe.
	ErrAmbiguousKID = errors.New("ambiguous JWK key ID")
)

// jwkIdentity identifies the role a JWK plays for verification. Two JWKs with the same "kid" can only coexist when
// their roles do not overlap, so a token header can never be matched by more than one of them.
type jwkIdentity struct {
	kid string
	use jwkset.USE
	alg jwkset.ALG
}

// validateJWKSet inspects a JWK Set before it is cached. Exact duplicate JWKs are collapsed, while distinct JWKs that
// share the same "kid" and overlap in "use" and "alg" are rejected. JWKs without a "kid" are left untouched, because
// they are never selected by a "kid" header and are handled through the full key set verification path.
//
// Two JWKs with the same "kid" are considered unambiguous only when their roles do not overlap: each must declare a
// different non-empty "use" and a different non-empty "alg". If either parameter is missing, or the values match, the
// token header alone cannot determine which key applies, so the set is ambiguous.
func validateJWKSet(jwks []jwkset.JWK) ([]jwkset.JWK, error) {
	seen := make(map[jwkIdentity]jwkset.JWKMarshal, len(jwks))
	unique := make([]jwkset.JWK, 0, len(jwks))
	for _, jwk := range jwks {
		marshal := jwk.Marshal()
		if marshal.KID == "" {
			unique = append(unique, jwk)
			continue
		}
		identity := jwkIdentity{
			kid: marshal.KID,
			use: marshal.USE,
			alg: marshal.ALG,
		}
		existing, ok := seen[identity]
		if ok {
			if !equalJWKMarshal(existing, marshal) {
				return nil, fmt.Errorf("%w: kid %q has multiple distinct keys for use %q and alg %q",
					ErrAmbiguousKID, marshal.KID, marshal.USE, marshal.ALG)
			}
			continue
		}
		for otherIdentity := range seen {
			if otherIdentity.kid != marshal.KID {
				continue
			}
			if !distinctRoles(otherIdentity, identity) {
				return nil, fmt.Errorf("%w: kid %q is used by keys with overlapping use/alg (%q/%q and %q/%q)",
					ErrAmbiguousKID, marshal.KID,
					otherIdentity.use, otherIdentity.alg, marshal.USE, marshal.ALG)
			}
		}
		seen[identity] = marshal
		unique = append(unique, jwk)
	}
	return unique, nil
}

// distinctRoles reports whether two JWKs sharing a "kid" are distinguishable by a token header. Both must declare a
// non-empty, different "use" and a non-empty, different "alg"; otherwise their roles overlap and the set is ambiguous.
func distinctRoles(a, b jwkIdentity) bool {
	return a.use != "" && b.use != "" && a.use != b.use &&
		a.alg != "" && b.alg != "" && a.alg != b.alg
}

// equalJWKMarshal reports whether two JWK marshal representations carry identical key material and metadata.
func equalJWKMarshal(a, b jwkset.JWKMarshal) bool {
	rawA, errA := json.Marshal(a)
	rawB, errB := json.Marshal(b)
	if errA != nil || errB != nil {
		return false
	}
	return string(rawA) == string(rawB)
}

// guardedStorage wraps a jwkset.Storage and rejects writes that would cache an ambiguous JWK Set. The wrapped storage
// is only mutated after the full snapshot has been validated, so a rejected refresh never partially updates the cache
// and the previously known good key set remains available.
type guardedStorage struct {
	jwkset.Storage
}

// newGuardedStorage wraps the given storage with duplicate "kid" ambiguity protection.
func newGuardedStorage(store jwkset.Storage) jwkset.Storage {
	if store == nil {
		store = jwkset.NewMemoryStorage()
	}
	return guardedStorage{Storage: store}
}

func (g guardedStorage) KeyReplaceAll(ctx context.Context, given []jwkset.JWK) error {
	validated, err := validateJWKSet(given)
	if err != nil {
		return err
	}
	return g.Storage.KeyReplaceAll(ctx, validated)
}

func (g guardedStorage) KeyWrite(ctx context.Context, jwk jwkset.JWK) error {
	existing, err := g.Storage.KeyReadAll(ctx)
	if err != nil {
		return fmt.Errorf("failed to snapshot keys before guarded write: %w", err)
	}
	validated, err := validateJWKSet(append(existing, jwk))
	if err != nil {
		return err
	}
	return g.Storage.KeyReplaceAll(ctx, validated)
}
