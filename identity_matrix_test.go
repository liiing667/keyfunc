package keyfunc

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
)

// fakeSigningMethod is a jwt.SigningMethod implementation that the keyfunc does not know. It lets the matrix prove
// that an unrecognized signing input fails closed before any key material is handed to a verifier.
type fakeSigningMethod struct{}

func (fakeSigningMethod) Verify(_ string, _ []byte, _ any) error { return nil }
func (fakeSigningMethod) Sign(_ string, _ any) ([]byte, error)   { return nil, nil }
func (fakeSigningMethod) Alg() string                            { return "FAKE" }

var _ jwt.SigningMethod = fakeSigningMethod{}

// identityMatrixFixture holds a fixed set of JWKs that exercise every identity dimension: alg, use, key_ops, and the
// signing input (key type and signing method).
type identityMatrixFixture struct {
	hmacSecret   []byte
	ecdsaPriv    *ecdsa.PrivateKey
	edPriv       ed25519.PrivateKey
	rsaPriv      *rsa.PrivateKey
	rotationPriv ed25519.PrivateKey
}

func newIdentityMatrixFixture(t *testing.T) identityMatrixFixture {
	t.Helper()
	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}
	_, rotationPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate rotation Ed25519 key pair: %v", err)
	}
	return identityMatrixFixture{
		hmacSecret:   []byte("matrix-hmac-secret"),
		ecdsaPriv:    ecdsaPriv,
		edPriv:       edPriv,
		rsaPriv:      rsaPriv,
		rotationPriv: rotationPriv,
	}
}

func mustWriteJWK(t *testing.T, ctx context.Context, store jwkset.Storage, key any, metadata jwkset.JWKMetadataOptions) {
	t.Helper()
	jwk, err := jwkset.NewJWKFromKey(key, jwkset.JWKOptions{
		Marshal:  jwkset.JWKMarshalOptions{Private: true},
		Metadata: metadata,
	})
	if err != nil {
		t.Fatalf("Failed to create JWK for kid %q: %v", metadata.KID, err)
	}
	if err = store.KeyWrite(ctx, jwk); err != nil {
		t.Fatalf("Failed to write JWK for kid %q: %v", metadata.KID, err)
	}
}

func signMatrixToken(t *testing.T, method jwt.SigningMethod, kid string, key any) string {
	t.Helper()
	token := jwt.New(method)
	if kid != "" {
		token.Header[jwkset.HeaderKID] = kid
	}
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("Failed to sign token with %s: %v", method.Alg(), err)
	}
	return signed
}

// TestIdentitySignatureMatrix pins the selection, rejection, and compatibility behavior of key identity binding.
// Every row uses a fixed key set and a fixed signing input so regressions are explicit rather than probabilistic.
func TestIdentitySignatureMatrix(t *testing.T) {
	ctx := context.Background()
	fixture := newIdentityMatrixFixture(t)

	const (
		kidHMAC           = "hmac-key"
		kidECDSA          = "ecdsa-key"
		kidEd             = "ed-key"
		kidRSA            = "rsa-key"
		kidEncOnly        = "enc-only"
		kidOpsNoVerify    = "ops-no-verify"
		kidMultiAlgorithm = "multi-alg"
		kidRotation       = "rotation"
		kidUnknownMethod  = "unknown-method"
		kidAlgPinnedHS512 = "pinned-hs512"
		kidAlgorithmPin   = "algorithm-pin"
	)

	store := jwkset.NewMemoryStorage()

	// Select rows: a key is usable when alg, use, key_ops, and the signing input line up.
	mustWriteJWK(t, ctx, store, fixture.hmacSecret, jwkset.JWKMetadataOptions{KID: kidHMAC, USE: jwkset.UseSig})
	mustWriteJWK(t, ctx, store, fixture.ecdsaPriv, jwkset.JWKMetadataOptions{KID: kidECDSA, USE: jwkset.UseSig})
	mustWriteJWK(t, ctx, store, fixture.edPriv, jwkset.JWKMetadataOptions{KID: kidEd, USE: jwkset.UseSig})
	mustWriteJWK(t, ctx, store, fixture.rsaPriv, jwkset.JWKMetadataOptions{KID: kidRSA, USE: jwkset.UseSig})

	// Reject rows: encryption-only use and key_ops without verify cannot validate a signature.
	mustWriteJWK(t, ctx, store, fixture.hmacSecret, jwkset.JWKMetadataOptions{KID: kidEncOnly, USE: jwkset.UseEnc})
	mustWriteJWK(t, ctx, store, fixture.hmacSecret, jwkset.JWKMetadataOptions{
		KID:    kidOpsNoVerify,
		USE:    jwkset.UseSig,
		KEYOPS: []jwkset.KEYOPS{jwkset.KeyOpsSign},
	})

	// Compatibility rows: the same kid is shared by a legitimate multi-algorithm key set and by an RSA key that
	// supports both PKCS#1 v1.5 and PSS.
	mustWriteJWK(t, ctx, store, fixture.hmacSecret, jwkset.JWKMetadataOptions{
		KID: kidMultiAlgorithm, ALG: jwkset.AlgHS256, USE: jwkset.UseSig,
	})
	mustWriteJWK(t, ctx, store, fixture.ecdsaPriv, jwkset.JWKMetadataOptions{
		KID: kidMultiAlgorithm, ALG: jwkset.AlgES256, USE: jwkset.UseSig,
	})
	mustWriteJWK(t, ctx, store, fixture.edPriv, jwkset.JWKMetadataOptions{
		KID: kidMultiAlgorithm, ALG: jwkset.AlgEdDSA, USE: jwkset.UseSig,
	})
	mustWriteJWK(t, ctx, store, fixture.hmacSecret, jwkset.JWKMetadataOptions{
		KID: kidAlgPinnedHS512, ALG: jwkset.AlgHS512, USE: jwkset.UseSig,
	})
	// A retired key kept under the same kid but pinned to an older algorithm must not satisfy a token intended for
	// the current key's algorithm. The two entries have different material and different pinned algs.
	retiredSecret := []byte("retired-hs256-secret")
	mustWriteJWK(t, ctx, store, retiredSecret, jwkset.JWKMetadataOptions{
		KID: kidAlgorithmPin, ALG: jwkset.AlgHS256, USE: jwkset.UseSig,
	})
	mustWriteJWK(t, ctx, store, fixture.hmacSecret, jwkset.JWKMetadataOptions{
		KID: kidAlgorithmPin, ALG: jwkset.AlgHS384, USE: jwkset.UseSig,
	})

	// Conflict rows: a retired key kept under the same kid and algorithm must not silently verify current tokens.
	mustWriteJWK(t, ctx, store, fixture.edPriv, jwkset.JWKMetadataOptions{KID: kidRotation, USE: jwkset.UseSig})
	mustWriteJWK(t, ctx, store, fixture.rotationPriv, jwkset.JWKMetadataOptions{KID: kidRotation, USE: jwkset.UseSig})
	mustWriteJWK(t, ctx, store, fixture.hmacSecret, jwkset.JWKMetadataOptions{KID: kidUnknownMethod, USE: jwkset.UseSig})

	k, err := New(Options{Ctx: ctx, Storage: store})
	if err != nil {
		t.Fatalf("Failed to create keyfunc: %v", err)
	}

	type matrixRow struct {
		name      string
		token     string
		wantErr   error
		wantValid bool
	}

	rows := []matrixRow{
		// Selection: each correctly bound identity verifies with its own signing input.
		{name: "select HMAC key", token: signMatrixToken(t, jwt.SigningMethodHS256, kidHMAC, fixture.hmacSecret), wantValid: true},
		{name: "select ECDSA key", token: signMatrixToken(t, jwt.SigningMethodES256, kidECDSA, fixture.ecdsaPriv), wantValid: true},
		{name: "select Ed25519 key", token: signMatrixToken(t, jwt.SigningMethodEdDSA, kidEd, fixture.edPriv), wantValid: true},
		{name: "select RSA key with RS256", token: signMatrixToken(t, jwt.SigningMethodRS256, kidRSA, fixture.rsaPriv), wantValid: true},
		{name: "select RSA key with PS256", token: signMatrixToken(t, jwt.SigningMethodPS256, kidRSA, fixture.rsaPriv), wantValid: true},

		// Rejection: metadata or signing input mismatches fail closed rather than falling through to another key.
		{name: "reject enc-only key", token: signMatrixToken(t, jwt.SigningMethodHS256, kidEncOnly, fixture.hmacSecret), wantErr: jwt.ErrTokenUnverifiable},
		{name: "reject key_ops without verify", token: signMatrixToken(t, jwt.SigningMethodHS256, kidOpsNoVerify, fixture.hmacSecret), wantErr: jwt.ErrTokenUnverifiable},
		{name: "reject alg pinned to HS512 for HS256", token: signMatrixToken(t, jwt.SigningMethodHS256, kidAlgPinnedHS512, fixture.hmacSecret), wantErr: jwt.ErrTokenUnverifiable},
		// The current HS384-pinned key still verifies a correctly signed HS384 token: pinning narrows, but does not
		// break, the legitimate algorithm of each key.
		{name: "select current key pinned to HS384", token: signMatrixToken(t, jwt.SigningMethodHS384, kidAlgorithmPin, fixture.hmacSecret), wantValid: true},
		// The retired key still verifies a token it genuinely signed, so per-key algorithm pinning narrows identity
		// without rejecting the retired key's own valid traffic.
		{name: "select retired key for its own HS256 token", token: signMatrixToken(t, jwt.SigningMethodHS256, kidAlgorithmPin, retiredSecret), wantValid: true},
		// An HS256 token only matches the retired entry; the current HS384-pinned entry is excluded by identity, so
		// verification proceeds with the retired key and fails on the signature instead of trusting the first lookup.
		{name: "reject HS256 token not signed by retired key", token: signMatrixToken(t, jwt.SigningMethodHS256, kidAlgorithmPin, fixture.hmacSecret), wantErr: jwt.ErrTokenSignatureInvalid},
		{name: "reject unknown kid", token: signMatrixToken(t, jwt.SigningMethodHS256, "missing-kid", fixture.hmacSecret), wantErr: jwt.ErrTokenUnverifiable},
		{name: "reject conflicting rotated key", token: signMatrixToken(t, jwt.SigningMethodEdDSA, kidRotation, fixture.rotationPriv), wantErr: jwt.ErrTokenUnverifiable},
		{name: "reject retired rotated key", token: signMatrixToken(t, jwt.SigningMethodEdDSA, kidRotation, fixture.edPriv), wantErr: jwt.ErrTokenUnverifiable},

		// Compatibility: a legitimate multi-algorithm set under one kid keeps every supported algorithm working.
		{name: "compatible multi-alg HS256", token: signMatrixToken(t, jwt.SigningMethodHS256, kidMultiAlgorithm, fixture.hmacSecret), wantValid: true},
		{name: "compatible multi-alg ES256", token: signMatrixToken(t, jwt.SigningMethodES256, kidMultiAlgorithm, fixture.ecdsaPriv), wantValid: true},
		{name: "compatible multi-alg EdDSA", token: signMatrixToken(t, jwt.SigningMethodEdDSA, kidMultiAlgorithm, fixture.edPriv), wantValid: true},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			parsed, parseErr := jwt.Parse(row.token, k.KeyfuncCtx(ctx))
			switch {
			case row.wantErr != nil:
				if !errors.Is(parseErr, row.wantErr) {
					t.Fatalf("Expected error %v, got %v", row.wantErr, parseErr)
				}
			case row.wantValid:
				if parseErr != nil || !parsed.Valid {
					t.Fatalf("Expected a valid token, got error %v", parseErr)
				}
			}
		})
	}

	// The parser rejects a header alg it does not recognize before calling keyfunc; assert the keyfunc layer itself
	// also fails closed when handed an unknown signing method directly.
	t.Run("reject unknown signing method", func(t *testing.T) {
		token := &jwt.Token{
			Header: map[string]any{"alg": "FAKE", jwkset.HeaderKID: kidUnknownMethod},
			Method: fakeSigningMethod{},
		}
		_, err := k.KeyfuncCtx(ctx)(token)
		if !errors.Is(err, ErrKeyfunc) {
			t.Fatalf("Expected ErrKeyfunc for unknown signing method, got %v", err)
		}
	})
}

// TestIdentityNoKIDMatrix ensures tokens without a kid still bind against the whole storage identity set.
func TestIdentityNoKIDMatrix(t *testing.T) {
	ctx := context.Background()
	fixture := newIdentityMatrixFixture(t)

	store := jwkset.NewMemoryStorage()
	mustWriteJWK(t, ctx, store, fixture.edPriv, jwkset.JWKMetadataOptions{KID: "ed-sig", USE: jwkset.UseSig})
	mustWriteJWK(t, ctx, store, fixture.hmacSecret, jwkset.JWKMetadataOptions{KID: "hmac-enc", USE: jwkset.UseEnc})

	k, err := New(Options{Ctx: ctx, Storage: store, UseWhitelist: []jwkset.USE{jwkset.UseSig}})
	if err != nil {
		t.Fatalf("Failed to create keyfunc: %v", err)
	}

	edToken := signMatrixToken(t, jwt.SigningMethodEdDSA, "", fixture.edPriv)
	parsed, err := jwt.Parse(edToken, k.KeyfuncCtx(ctx))
	if err != nil || !parsed.Valid {
		t.Fatalf("Expected no-kid EdDSA token to validate, got error %v", err)
	}

	// The HMAC key is marked for encryption and excluded by the use whitelist, so no identity survives.
	hmacToken := signMatrixToken(t, jwt.SigningMethodHS256, "", fixture.hmacSecret)
	_, err = jwt.Parse(hmacToken, k.KeyfuncCtx(ctx))
	if !errors.Is(err, jwt.ErrTokenUnverifiable) {
		t.Fatalf("Expected jwt.ErrTokenUnverifiable for no-kid token without a matching identity, got %v", err)
	}
}
