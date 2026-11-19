package keyfunc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"slices"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/time/rate"
)

var (
	// ErrKeyfunc is returned when a keyfunc error occurs.
	ErrKeyfunc = errors.New("failed keyfunc")
)

// Keyfunc is meant to be used as the jwt.Keyfunc function for github.com/golang-jwt/jwt/v5. It uses
// github.com/MicahParks/jwkset as a JWK Set storage.
type Keyfunc interface {
	Keyfunc(token *jwt.Token) (any, error)
	KeyfuncCtx(ctx context.Context) jwt.Keyfunc
	Storage() jwkset.Storage
	VerificationKeySet(ctx context.Context) (jwt.VerificationKeySet, error)
}

// Options are used to create a new Keyfunc.
type Options struct {
	Ctx          context.Context
	Storage      jwkset.Storage
	UseWhitelist []jwkset.USE
}

// Override is used to change specific default behaviors.
type Override struct {
	// Client is from https://pkg.go.dev/github.com/MicahParks/jwkset#HTTPClientStorageOptions
	Client *http.Client
	// Given is from https://pkg.go.dev/github.com/MicahParks/jwkset#HTTPClientOptions
	Given jwkset.Storage
	// HTTPTimeout is from https://pkg.go.dev/github.com/MicahParks/jwkset#HTTPClientStorageOptions
	HTTPTimeout time.Duration
	// NoErrorReturnFirstHTTPReq is from https://pkg.go.dev/github.com/MicahParks/jwkset#HTTPClientStorageOptions
	NoErrorReturnFirstHTTPReq *bool
	// PrioritizeHTTP is from https://pkg.go.dev/github.com/MicahParks/jwkset#HTTPClientOptions
	PrioritizeHTTP bool
	// RateLimitWaitMax is from https://pkg.go.dev/github.com/MicahParks/jwkset#HTTPClientOptions
	RateLimitWaitMax time.Duration
	// RefreshErrorHandlerFunc is a function that accepts the URL of the remote JWK Set storage and returns the
	// RefreshErrorHandler from https://pkg.go.dev/github.com/MicahParks/jwkset#HTTPClientStorageOptions
	RefreshErrorHandlerFunc func(u string) func(ctx context.Context, err error)
	// RefreshInterval is from https://pkg.go.dev/github.com/MicahParks/jwkset#HTTPClientStorageOptions
	RefreshInterval time.Duration
	// RefreshUnknownKID is from https://pkg.go.dev/github.com/MicahParks/jwkset#HTTPClientOptions
	RefreshUnknownKID *rate.Limiter
	// ValidationSkipAll is copied to SkipAll in https://pkg.go.dev/github.com/MicahParks/jwkset#JWKValidateOptions
	ValidationSkipAll bool
}

type keyfunc struct {
	ctx          context.Context
	storage      jwkset.Storage
	useWhitelist []jwkset.USE
}

// New creates a new Keyfunc.
func New(options Options) (Keyfunc, error) {
	ctx := options.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if options.Storage == nil {
		return nil, fmt.Errorf("%w: no JWK Set storage given in options", ErrKeyfunc)
	}
	k := keyfunc{
		ctx:          ctx,
		storage:      options.Storage,
		useWhitelist: options.UseWhitelist,
	}
	return k, nil
}

// NewDefault creates a new Keyfunc with a default JWK Set storage and options.
//
// This will launch "refresh goroutine" to automatically refresh the remote HTTP resources.
func NewDefault(urls []string) (Keyfunc, error) {
	return NewDefaultCtx(context.Background(), urls)
}

// NewDefaultCtx creates a new Keyfunc with a default JWK Set storage and options. The context is used to end the
// "refresh goroutine".
//
// This will launch "refresh goroutine" to automatically refresh the remote HTTP resources.
func NewDefaultCtx(ctx context.Context, urls []string) (Keyfunc, error) {
	client, err := jwkset.NewDefaultHTTPClientCtx(ctx, urls)
	if err != nil {
		return nil, err
	}
	options := Options{
		Storage: client,
	}
	return New(options)
}

// NewDefaultOverrideCtx creates a new Keyfunc with a default JWK Set storage and options. The context is used to end
// the "refresh goroutine". The override parameter is used to change specific default behaviors.
//
// This will launch "refresh goroutine" to automatically refresh remote HTTP resources.
func NewDefaultOverrideCtx(ctx context.Context, urls []string, override Override) (Keyfunc, error) {
	rateLimitWaitMax := time.Minute
	if override.RateLimitWaitMax != 0 {
		rateLimitWaitMax = override.RateLimitWaitMax
	}
	refreshErrorHandler := func(u string) func(ctx context.Context, err error) {
		return func(ctx context.Context, err error) {
			slog.Default().ErrorContext(ctx, "Failed to refresh HTTP JWK Set from remote HTTP resource.",
				"error", err,
				"url", u,
			)
		}
	}
	if override.RefreshErrorHandlerFunc != nil {
		refreshErrorHandler = override.RefreshErrorHandlerFunc
	}
	refreshInterval := time.Hour
	if override.RefreshInterval > 0 {
		refreshInterval = override.RefreshInterval
	}
	refreshUnknownKID := rate.NewLimiter(rate.Every(5*time.Minute), 1)
	if override.RefreshUnknownKID != nil {
		refreshUnknownKID = override.RefreshUnknownKID
	}
	noErrorReturnFirstHTTPReq := true
	if override.NoErrorReturnFirstHTTPReq != nil {
		noErrorReturnFirstHTTPReq = *override.NoErrorReturnFirstHTTPReq
	}

	clientOptions := jwkset.HTTPClientOptions{
		Given:             override.Given,
		HTTPURLs:          make(map[string]jwkset.Storage),
		PrioritizeHTTP:    override.PrioritizeHTTP,
		RateLimitWaitMax:  rateLimitWaitMax,
		RefreshUnknownKID: refreshUnknownKID,
	}
	for _, u := range urls {
		errorHandler := refreshErrorHandler(u)
		options := jwkset.HTTPClientStorageOptions{
			Client:                    override.Client,
			Ctx:                       ctx,
			NoErrorReturnFirstHTTPReq: noErrorReturnFirstHTTPReq,
			RefreshErrorHandler:       errorHandler,
			RefreshInterval:           refreshInterval,
			ValidateOptions: jwkset.JWKValidateOptions{
				SkipAll: override.ValidationSkipAll,
			},
		}

		if override.HTTPTimeout > 0 {
			options.HTTPTimeout = override.HTTPTimeout
		}

		c, err := jwkset.NewStorageFromHTTP(u, options)
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP client storage for %q: %w", u, errors.Join(err, jwkset.ErrNewClient))
		}
		clientOptions.HTTPURLs[u] = c
	}
	storage, err := jwkset.NewHTTPClient(clientOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client storage: %w", errors.Join(err, jwkset.ErrNewClient))
	}
	options := Options{
		Ctx:          ctx,
		Storage:      storage,
		UseWhitelist: nil,
	}
	return New(options)
}

// NewJWKJSON creates a new Keyfunc from raw JWK JSON.
func NewJWKJSON(raw json.RawMessage) (Keyfunc, error) {
	marshalOptions := jwkset.JWKMarshalOptions{
		Private: true,
	}
	jwk, err := jwkset.NewJWKFromRawJSON(raw, marshalOptions, jwkset.JWKValidateOptions{})
	if err != nil {
		return nil, fmt.Errorf("%w: could not create JWK from raw JSON", errors.Join(err, ErrKeyfunc))
	}
	store := jwkset.NewMemoryStorage()
	err = store.KeyWrite(context.Background(), jwk)
	if err != nil {
		return nil, fmt.Errorf("%w: could not write JWK to storage", errors.Join(err, ErrKeyfunc))
	}
	options := Options{
		Storage: store,
	}
	return New(options)
}

// NewJWKSetJSON creates a new Keyfunc from raw JWK Set JSON.
func NewJWKSetJSON(raw json.RawMessage) (Keyfunc, error) {
	var jwks jwkset.JWKSMarshal
	err := json.Unmarshal(raw, &jwks)
	if err != nil {
		return nil, fmt.Errorf("%w: could not unmarshal raw JWK Set JSON", errors.Join(err, ErrKeyfunc))
	}
	store, err := jwks.ToStorage()
	if err != nil {
		return nil, fmt.Errorf("%w: could not create JWK Set storage", errors.Join(err, ErrKeyfunc))
	}
	options := Options{
		Storage: store,
	}
	return New(options)
}

func (k keyfunc) KeyfuncCtx(ctx context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		algInter, ok := token.Header["alg"]
		if !ok {
			return nil, fmt.Errorf("%w: could not find alg in JWT header", ErrKeyfunc)
		}
		alg, ok := algInter.(string)
		if !ok {
			// For test coverage purposes, this should be impossible to reach because the JWT package rejects a token
			// without an alg parameter in the header before calling jwt.Keyfunc.
			return nil, fmt.Errorf(`%w: the JWT header did not contain the "alg" parameter, which is required by RFC 7515 section 4.1.1`, ErrKeyfunc)
		}

		var (
			candidates []jwkset.JWK
			err        error
		)
		kid := ""
		kidInter, ok := token.Header[jwkset.HeaderKID]
		if !ok {
			candidates, err = k.storage.KeyReadAll(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to read all JWK from storage: %w", errors.Join(err, ErrKeyfunc))
			}
		} else {
			kid, ok = kidInter.(string)
			if !ok {
				return nil, fmt.Errorf("%w: could not convert kid in JWT header to string", ErrKeyfunc)
			}
			candidates, err = k.candidatesForKID(ctx, kid)
			if err != nil {
				return nil, err
			}
		}

		keySet, err := k.verificationKeys(token.Method, alg, kid, candidates, true)
		if err != nil {
			return nil, err
		}
		if len(keySet.Keys) == 1 {
			return keySet.Keys[0], nil
		}
		return keySet, nil
	}
}
func (k keyfunc) Keyfunc(token *jwt.Token) (any, error) {
	keyF := k.KeyfuncCtx(k.ctx)
	return keyF(token)
}
func (k keyfunc) Storage() jwkset.Storage {
	return k.storage
}
func (k keyfunc) VerificationKeySet(ctx context.Context) (jwt.VerificationKeySet, error) {
	jwks, err := k.storage.KeyReadAll(ctx)
	if err != nil {
		return jwt.VerificationKeySet{}, fmt.Errorf("failed to read all JWK from storage: %w", errors.Join(err, ErrKeyfunc))
	}
	return k.verificationKeys(nil, "", "", jwks, false)
}

// candidatesForKID returns every JWK in storage that carries the given kid. KeyRead is preferred so that the refresh
// and priority behavior of the underlying storage is preserved, but every other JWK sharing the same kid is still
// enumerated. Enumerating the whole set instead of trusting the first match prevents a shadowed or retired key from
// silently deciding the key identity.
func (k keyfunc) candidatesForKID(ctx context.Context, kid string) ([]jwkset.JWK, error) {
	first, err := k.storage.KeyRead(ctx, kid)
	if err != nil {
		return nil, fmt.Errorf("%w: could not read JWK from storage", errors.Join(err, ErrKeyfunc))
	}
	all, err := k.storage.KeyReadAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read all JWK from storage: %w", errors.Join(err, ErrKeyfunc))
	}
	candidates := make([]jwkset.JWK, 0, 1)
	for _, j := range all {
		if j.Marshal().KID == kid {
			candidates = append(candidates, j)
		}
	}
	if len(candidates) == 0 {
		candidates = append(candidates, first)
	}
	return candidates, nil
}

// verificationKeys binds the token's signing input (method and alg) together with each candidate JWK's alg, use, and
// key_ops parameters into a single key identity. Candidates that cannot participate in signature verification are
// rejected before any signature is checked. When kid is non-empty, every surviving candidate must represent the same
// key material; otherwise the identity is ambiguous and verification fails closed. A nil method skips the signing
// input and conflict checks, which is only used by VerificationKeySet without a token context.
func (k keyfunc) verificationKeys(method jwt.SigningMethod, alg, kid string, candidates []jwkset.JWK, tokenContext bool) (jwt.VerificationKeySet, error) {
	if tokenContext && !isKnownSigningMethod(method) {
		return jwt.VerificationKeySet{}, fmt.Errorf(`%w: unknown or unsupported JWT signing method %q`, ErrKeyfunc, method.Alg())
	}

	var keySet jwt.VerificationKeySet
	var acceptedMaterial any
	for _, candidate := range candidates {
		if !k.identityMatches(candidate, method, alg, tokenContext) {
			continue
		}
		publicKey := publicMaterial(candidate)
		if tokenContext && kid != "" && acceptedMaterial != nil && !reflect.DeepEqual(acceptedMaterial, publicKey) {
			return jwt.VerificationKeySet{}, fmt.Errorf(
				`%w: multiple JWKs with kid %q match token alg %q but contain different key material; refusing to verify an ambiguous key identity`,
				ErrKeyfunc, kid, alg)
		}
		acceptedMaterial = publicKey

		duplicate := false
		for _, existing := range keySet.Keys {
			if reflect.DeepEqual(existing, publicKey) {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		keySet.Keys = append(keySet.Keys, publicKey)
	}

	if len(keySet.Keys) == 0 {
		if kid != "" {
			return jwt.VerificationKeySet{}, fmt.Errorf(
				`%w: no JWK with kid %q forms a matching identity for token alg %q (check alg, use, key_ops, and key type)`,
				ErrKeyfunc, kid, alg)
		}
		return jwt.VerificationKeySet{}, fmt.Errorf(
			`%w: no JWK in storage forms a matching identity for token alg %q (check alg, use, key_ops, and key type)`,
			ErrKeyfunc, alg)
	}
	return keySet, nil
}

// identityMatches reports whether the alg, use, key_ops, and signing input of a JWK jointly match the token's identity.
// Every failure mode rejects the candidate rather than falling back to another interpretation.
func (k keyfunc) identityMatches(candidate jwkset.JWK, method jwt.SigningMethod, alg string, tokenContext bool) bool {
	metadata := candidate.Marshal()

	// A JWK that pins an alg can only verify tokens using that exact algorithm.
	if tokenContext && metadata.ALG.String() != "" && metadata.ALG.String() != alg {
		return false
	}

	// Signature verification requires a signing key. Keys explicitly marked for encryption are rejected, while keys
	// without a use parameter remain usable subject to the configured whitelist.
	if metadata.USE != "" && metadata.USE != jwkset.UseSig {
		return false
	}
	if !k.useAllowed(candidate) {
		return false
	}

	// When key_ops is present, it must authorize the verify operation per RFC 7517 section 4.3. An absent key_ops
	// parameter imposes no operation restriction.
	if len(metadata.KEYOPS) > 0 && !slices.Contains(metadata.KEYOPS, jwkset.KeyOpsVerify) {
		return false
	}

	// The key type must be compatible with the token's signing method before verification is attempted. This closes
	// algorithm-confusion paths such as feeding an HMAC secret into an RSA verifier or vice versa.
	if tokenContext && !keyTypeMatchesMethod(publicMaterial(candidate), method) {
		return false
	}
	return true
}

func (k keyfunc) useAllowed(jwk jwkset.JWK) bool {
	return len(k.useWhitelist) == 0 || slices.Contains(k.useWhitelist, jwk.Marshal().USE)
}

func publicMaterial(jwk jwkset.JWK) any {
	key := jwk.Key()
	if pk, ok := key.(publicKeyer); ok {
		return pk.Public()
	}
	return key
}

func isKnownSigningMethod(method jwt.SigningMethod) bool {
	switch method.(type) {
	case *jwt.SigningMethodHMAC, *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS,
		*jwt.SigningMethodECDSA, *jwt.SigningMethodEd25519:
		return true
	}
	return false
}

func keyTypeMatchesMethod(key any, method jwt.SigningMethod) bool {
	switch method.(type) {
	case *jwt.SigningMethodHMAC:
		_, ok := key.([]byte)
		return ok
	case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS:
		_, ok := key.(*rsa.PublicKey)
		return ok
	case *jwt.SigningMethodECDSA:
		_, ok := key.(*ecdsa.PublicKey)
		return ok
	case *jwt.SigningMethodEd25519:
		_, ok := key.(ed25519.PublicKey)
		return ok
	}
	return false
}

type publicKeyer interface {
	Public() crypto.PublicKey
}
