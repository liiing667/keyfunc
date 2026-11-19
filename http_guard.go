package keyfunc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/MicahParks/jwkset"
)

// newGuardedStorageFromHTTP creates the remote JWK Set storage used by the default keyfunc constructors. Every cached
// snapshot is routed through validateJWKSet by the guarded storage, so an ambiguous response fails to update the cache.
//
// jwkset.NewStorageFromHTTP performs the first request synchronously. When that request returns an ambiguous JWK Set,
// the guarded storage rejects the write and jwkset surfaces the ErrAmbiguousKID error directly. If first-request
// errors are tolerated, an ambiguous snapshot leaves the cache empty, which is re-checked here so the constructor
// still fails closed instead of returning a keyfunc that can never verify a token.
func newGuardedStorageFromHTTP(remoteJWKSetURL string, options jwkset.HTTPClientStorageOptions) (jwkset.Storage, error) {
	options.Storage = newGuardedStorage(options.Storage)
	if options.Ctx == nil {
		options.Ctx = context.Background()
	}

	// When jwkset is asked to tolerate a failed first HTTP request, it also swallows a guarded ambiguity error and
	// leaves the cache empty. Pre-fetch the first response here so ErrAmbiguousKID still fails the constructor closed.
	if options.NoErrorReturnFirstHTTPReq {
		if err := validateRemoteJWKSet(options.Ctx, remoteJWKSetURL, options); err != nil {
			return nil, err
		}
	}

	store, err := jwkset.NewStorageFromHTTP(remoteJWKSetURL, options)
	if err != nil {
		return nil, err
	}

	// A tolerated first-request error (for example the server was briefly unavailable) leaves an empty cache. Re-validate
	// the snapshot so an ambiguity that jwkset did not surface is still rejected at construction time.
	snapshot, readErr := store.KeyReadAll(options.Ctx)
	if readErr != nil {
		return nil, fmt.Errorf("failed to snapshot initial JWK Set: %w", readErr)
	}
	if _, validateErr := validateJWKSet(snapshot); validateErr != nil {
		return nil, validateErr
	}
	return store, nil
}

// validateRemoteJWKSet fetches the remote JWK Set once and applies the same ambiguity check the guarded storage uses
// on every refresh. Transient HTTP errors are ignored here, because they are covered by the tolerated first-request
// behavior; only a structurally ambiguous response is rejected.
func validateRemoteJWKSet(ctx context.Context, remoteJWKSetURL string, options jwkset.HTTPClientStorageOptions) error {
	client := options.Client
	if client == nil {
		client = http.DefaultClient
	}
	method := options.HTTPMethod
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, remoteJWKSetURL, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	//goland:noinspection GoUnhandledErrorResult
	defer resp.Body.Close()
	expectedStatus := options.HTTPExpectedStatus
	if expectedStatus == 0 {
		expectedStatus = http.StatusOK
	}
	if resp.StatusCode != expectedStatus {
		return nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	var jwks jwkset.JWKSMarshal
	if err = json.Unmarshal(body, &jwks); err != nil {
		return nil
	}
	slice, err := jwks.JWKSlice()
	if err != nil {
		return nil
	}
	_, err = validateJWKSet(slice)
	return err
}
