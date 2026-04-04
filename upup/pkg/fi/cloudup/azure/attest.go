/*
Copyright 2026 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package azure

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/smallstep/pkcs7"
	expirationcache "k8s.io/client-go/tools/cache"
)

const (
	// attestedDocumentTimeFormat is the timestamp format used by the Azure IMDS attested document.
	attestedDocumentTimeFormat = "01/02/06 15:04:05 -0700"

	// attestedDocumentNonceLength is the length of the hex-encoded SHA256 prefix
	// used as the Azure IMDS attested document nonce. IMDS enforces a 32-character
	// maximum for the nonce parameter; 32 hex chars is 128 bits of entropy, well
	// above the cryptographic nonce floor.
	attestedDocumentNonceLength = 32

	azureMetadataDNSName         = "metadata.azure.com"
	azureMetadataSubdomainSuffix = ".metadata.azure.com"

	// microsoftIntermediateCertBaseURL is the only location we should consult
	// when constructing Azure metadata intermediate certificate URLs.
	microsoftIntermediateCertBaseURL = "https://www.microsoft.com/pkiops/certs"

	// intermediateCertRefreshInterval is how long intermediate CA certificates
	// are cached before re-fetching from the Microsoft PKI repository. Microsoft
	// rotates intermediate CAs infrequently (typically yearly), so 24 hours
	// keeps the cache fresh without unnecessary network requests.
	intermediateCertRefreshInterval = 24 * time.Hour

	// intermediateCertNegativeCacheInterval is how long a failed intermediate
	// fetch result is cached. Short enough to recover from a transient Microsoft
	// PKI blip, long enough to stop an attacker from using bogus AIA URLs to
	// amplify network fetches via repeated verification attempts.
	intermediateCertNegativeCacheInterval = 5 * time.Minute

	// intermediateCertMaxResponseBytes caps the body size accepted from an
	// intermediate certificate fetch. Real Microsoft PKI intermediates are
	// ~1.5 KB in DER; 16 KiB leaves ample headroom while preventing a
	// pathological response from consuming memory.
	intermediateCertMaxResponseBytes = 16 * 1024
)

var (
	// intermediateCertPositiveCache caches successful intermediate fetches.
	// intermediateCertNegativeCache caches recent fetch failures for a shorter
	// window, keyed the same way, so attackers cannot amplify fetches via bogus
	// AIA URLs. Stores are read positive-first; transient overlap is harmless.
	intermediateCertPositiveCache = expirationcache.NewTTLStore(
		intermediateCertCacheEntryKeyFunc, intermediateCertRefreshInterval)
	intermediateCertNegativeCache = expirationcache.NewTTLStore(
		intermediateCertCacheEntryKeyFunc, intermediateCertNegativeCacheInterval)

	cachedSystemCertPool *x509.CertPool
	cachedSystemMu       sync.Mutex

	// Reuse one client for intermediate fetches so each lookup does not build a
	// new transport stack. The allowlist lives in URL validation, not in the client.
	intermediateCertHTTPClient = &http.Client{Timeout: 10 * time.Second}
)

// intermediateCacheKey scopes the cache to the issuing CA identity rather than
// the leaf signer. Caching by issuer avoids refetching for every leaf, while
// RawIssuer and AuthorityKeyId together distinguish issuers that may share
// names across renewals or cross-signs.
type intermediateCacheKey struct {
	rawIssuer      string
	authorityKeyID string
}

// intermediateCertCacheEntry is the object stored in the TTLStore caches. A
// nil pool marks a negative entry (a cached fetch failure).
type intermediateCertCacheEntry struct {
	key  intermediateCacheKey
	pool *x509.CertPool
}

// intermediateCertCacheEntryKeyFunc is the TTLStore key function for cache
// entries. \x00 is used as a separator since neither field can contain it in
// valid x509 content.
func intermediateCertCacheEntryKeyFunc(obj any) (string, error) {
	e, ok := obj.(*intermediateCertCacheEntry)
	if !ok {
		return "", fmt.Errorf("unexpected cache entry type %T", obj)
	}
	return e.key.rawIssuer + "\x00" + e.key.authorityKeyID, nil
}

// attestedData is the JSON content inside the PKCS7 signed data from the IMDS attested document.
type attestedData struct {
	VMId           string            `json:"vmId"`
	SubscriptionId string            `json:"subscriptionId"`
	Nonce          string            `json:"nonce"`
	TimeStamp      attestedTimeStamp `json:"timeStamp"`
}

// attestedTimeStamp represents the creation and expiration time of the attested document.
type attestedTimeStamp struct {
	CreatedOn string `json:"createdOn"`
	ExpiresOn string `json:"expiresOn"`
}

// verifyAttestedDocument verifies a PKCS7 attested document using the system
// root certificate pool, first trying the embedded PKCS7 chain and only
// falling back to Microsoft PKI when intermediates are missing.
func verifyAttestedDocument(signature string, body []byte) (*attestedData, error) {
	rootCertPool, err := systemCertPool()
	if err != nil {
		return nil, err
	}

	return verifyAttestedDocumentWithRootAndFetcher(signature, body, rootCertPool, intermediateCertPoolForSigner)
}

// verifyAttestedDocumentWithRootAndFetcher verifies a PKCS7 attested document
// using the supplied root pool and intermediate fetcher. It prefers the
// embedded PKCS7 certificates and only consults the fetcher when the embedded
// chain does not already verify.
func verifyAttestedDocumentWithRootAndFetcher(signature string, body []byte, rootCertPool *x509.CertPool, fetchIntermediates func(*x509.Certificate) (*x509.CertPool, error)) (*attestedData, error) {
	if rootCertPool == nil {
		return nil, fmt.Errorf("root certificate pool is required")
	}
	if fetchIntermediates == nil {
		return nil, fmt.Errorf("intermediate certificate fetch function is required")
	}

	p7, signer, err := parseAndValidatePKCS7Signer(signature)
	if err != nil {
		return nil, err
	}

	embeddedOnlyIntermediates := x509.NewCertPool()
	if err := verifySignerCertChain(signer, p7.Certificates, rootCertPool, embeddedOnlyIntermediates); err != nil {
		// Signer SAN was validated above; only now is it safe to hit the network.
		intermediateCerts, fetchErr := fetchIntermediates(signer)
		if fetchErr != nil {
			return nil, fmt.Errorf("verifying PKCS7 certificate chain: embedded=%w; fetch=%w", err, fetchErr)
		}
		if err := verifySignerCertChain(signer, p7.Certificates, rootCertPool, intermediateCerts); err != nil {
			return nil, fmt.Errorf("verifying PKCS7 certificate chain: %w", err)
		}
	}

	return parseAndValidateAttestedDocumentContent(p7.Content, body)
}

// verifyAttestedDocumentWithCertPools verifies a base64-encoded PKCS7 attested
// document using caller-supplied root and intermediate certificate pools.
func verifyAttestedDocumentWithCertPools(signature string, body []byte, rootCertPool *x509.CertPool, intermediateCerts *x509.CertPool) (*attestedData, error) {
	if rootCertPool == nil {
		return nil, fmt.Errorf("root certificate pool is required")
	}
	if intermediateCerts == nil {
		return nil, fmt.Errorf("intermediate certificate pool is required")
	}

	p7, signer, err := parseAndValidatePKCS7Signer(signature)
	if err != nil {
		return nil, err
	}

	if err := verifySignerCertChain(signer, p7.Certificates, rootCertPool, intermediateCerts); err != nil {
		return nil, fmt.Errorf("verifying PKCS7 certificate chain: %w", err)
	}

	return parseAndValidateAttestedDocumentContent(p7.Content, body)
}

// parseAndValidatePKCS7Signer decodes and parses a base64-encoded PKCS7
// signature, verifies its self-signature, and validates that the signer
// certificate's SAN identifies an Azure metadata endpoint. All checks here
// are CPU-only; no network I/O is performed, so this is safe to call before
// triggering intermediate certificate fetches.
func parseAndValidatePKCS7Signer(signature string) (*pkcs7.PKCS7, *x509.Certificate, error) {
	if signature == "" {
		return nil, nil, fmt.Errorf("empty PKCS7 signature")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding PKCS7 signature: %w", err)
	}

	p7, err := pkcs7.Parse(sigBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing PKCS7 signature: %w", err)
	}

	// Verify the PKCS7 signature against the embedded leaf certificate.
	if err := p7.Verify(); err != nil {
		return nil, nil, fmt.Errorf("verifying PKCS7 signature: %w", err)
	}

	signer := p7.GetOnlySigner()
	if signer == nil {
		return nil, nil, fmt.Errorf("getting PKCS7 signer certificate")
	}
	if err := validateAzureMetadataSignerSAN(signer); err != nil {
		return nil, nil, fmt.Errorf("validating PKCS7 signer SAN: %w", err)
	}

	return p7, signer, nil
}

// nonceForBody derives the IMDS attestation nonce from the request body.
// Must be identical on the authenticator and verifier sides.
func nonceForBody(body []byte) string {
	hash := sha256.Sum256(body)
	return hex.EncodeToString(hash[:])[:attestedDocumentNonceLength]
}

// parseAndValidateAttestedDocumentContent unmarshals the signed attestation
// payload and validates its nonce and expiration.
func parseAndValidateAttestedDocumentContent(content []byte, body []byte) (*attestedData, error) {
	// Extract and validate the signed attested data.
	var data attestedData
	if err := json.Unmarshal(content, &data); err != nil {
		return nil, fmt.Errorf("unmarshalling attested data: %w", err)
	}

	// Verify the nonce matches the request body hash (replay protection).
	if data.Nonce != nonceForBody(body) {
		return nil, fmt.Errorf("attested document nonce mismatch")
	}

	// Verify the attested document has not expired.
	if data.TimeStamp.ExpiresOn != "" {
		expiresOn, err := time.Parse(attestedDocumentTimeFormat, data.TimeStamp.ExpiresOn)
		if err != nil {
			return nil, fmt.Errorf("parsing attested document expiration: %w", err)
		}
		if time.Now().After(expiresOn) {
			return nil, fmt.Errorf("attested document expired at %s", data.TimeStamp.ExpiresOn)
		}
	}

	return &data, nil
}

// systemCertPool returns a cached system root certificate pool,
// loading it on first call.
func systemCertPool() (*x509.CertPool, error) {
	cachedSystemMu.Lock()
	defer cachedSystemMu.Unlock()

	if cachedSystemCertPool != nil {
		return cachedSystemCertPool, nil
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("loading system certificate pool: %w", err)
	}

	cachedSystemCertPool = pool
	return pool, nil
}

// intermediateCertPoolForSigner returns intermediates for the signer's issuer
// using the package-level TTL caches, fetching from Microsoft PKI on miss.
func intermediateCertPoolForSigner(signer *x509.Certificate) (*x509.CertPool, error) {
	return intermediateCertPoolWithCaches(signer, fetchIntermediateCerts, intermediateCertPositiveCache, intermediateCertNegativeCache)
}

// intermediateCertPoolWithCaches performs a cached lookup against the supplied
// positive and negative TTL caches, invoking fetch on a miss. Tests inject
// their own stores and fetchers.
func intermediateCertPoolWithCaches(signer *x509.Certificate, fetch func(*x509.Certificate) (*x509.CertPool, error), positive, negative expirationcache.Store) (*x509.CertPool, error) {
	if signer == nil {
		return nil, fmt.Errorf("signer certificate is required")
	}
	if fetch == nil {
		return nil, fmt.Errorf("intermediate certificate fetch function is required")
	}
	if positive == nil || negative == nil {
		return nil, fmt.Errorf("intermediate certificate caches are required")
	}

	entry := &intermediateCertCacheEntry{key: intermediateCacheKey{
		rawIssuer:      string(signer.RawIssuer),
		authorityKeyID: string(signer.AuthorityKeyId),
	}}
	keyStr, err := intermediateCertCacheEntryKeyFunc(entry)
	if err != nil {
		return nil, err
	}

	// Positive cache wins over negative: a successful later fetch overwrites
	// any stale negative entry, which expires on its own shorter TTL.
	if obj, ok, _ := positive.GetByKey(keyStr); ok {
		return obj.(*intermediateCertCacheEntry).pool, nil
	}
	if _, ok, _ := negative.GetByKey(keyStr); ok {
		return nil, fmt.Errorf("intermediate certificate fetch recently failed for signer issuer (cached)")
	}

	pool, fetchErr := fetch(signer)
	entry.pool = pool
	if fetchErr != nil {
		// List() walks every entry and lazily deletes expired ones; ListKeys()
		// would not trigger expiration. Doing this before each write bounds
		// cache memory to ~(write_rate × TTL) without a background goroutine,
		// which matters most for the negative cache since an attacker rotating
		// issuer keys can drive writes to it at the fetch rate. Cost is O(N)
		// per write, so in attack conditions writes become slower as the cache
		// grows, which also acts as a natural rate limit. For legitimate
		// traffic (a handful of entries), this is effectively free.
		_ = negative.List()
		_ = negative.Add(entry)
		return nil, fetchErr
	}
	// Positive cache writes are rare and bounded to the legitimate Microsoft
	// PKI issuer set, so this List() is symmetric with the negative path but
	// essentially free in practice.
	_ = positive.List()
	_ = positive.Add(entry)
	return pool, nil
}

// fetchIntermediateCerts fetches intermediate CA certificates from validated
// Microsoft PKI AIA URLs from the signer certificate.
func fetchIntermediateCerts(signer *x509.Certificate) (*x509.CertPool, error) {
	return fetchIntermediateCertsFromBaseURL(intermediateCertHTTPClient, microsoftIntermediateCertBaseURL, signer)
}

// fetchIntermediateCertsFromBaseURL collects validated Microsoft PKI AIA URLs
// for the signer, downloads each certificate, and keeps only those that match
// the signer's issuer identity.
func fetchIntermediateCertsFromBaseURL(client *http.Client, baseURL string, signer *x509.Certificate) (*x509.CertPool, error) {
	if client == nil {
		return nil, fmt.Errorf("HTTP client is required")
	}
	if signer == nil {
		return nil, fmt.Errorf("signer certificate is required")
	}

	urls, err := microsoftIntermediateCandidateURLs(baseURL, signer)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	matched := 0
	for _, url := range urls {
		cert, err := fetchCertificate(client, url)
		if err != nil {
			return nil, err
		}
		if err := validateFetchedIntermediateForSigner(signer, cert); err != nil {
			continue
		}
		pool.AddCert(cert)
		matched++
	}
	if matched == 0 {
		return nil, fmt.Errorf("no fetched intermediate certificates matched signer issuer")
	}

	return pool, nil
}

// fetchCertificate fetches and parses a DER-encoded certificate from the given URL.
func fetchCertificate(client *http.Client, url string) (*x509.Certificate, error) {
	if client == nil {
		return nil, fmt.Errorf("HTTP client is required")
	}
	if url == "" {
		return nil, fmt.Errorf("certificate URL is required")
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetching intermediate certificate from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching intermediate certificate from %s: status=%d", url, resp.StatusCode)
	}

	// Cap the body read to reject pathologically large responses. Read one
	// extra byte so we can distinguish "at the limit" from "exceeded limit".
	body, err := io.ReadAll(io.LimitReader(resp.Body, intermediateCertMaxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading intermediate certificate from %s: %w", url, err)
	}
	if len(body) > intermediateCertMaxResponseBytes {
		return nil, fmt.Errorf("intermediate certificate from %s exceeds %d bytes", url, intermediateCertMaxResponseBytes)
	}

	return x509.ParseCertificate(body)
}

// validateFetchedIntermediateForSigner checks that a fetched intermediate is
// actually the issuer referenced by the signer certificate before it is used or cached.
func validateFetchedIntermediateForSigner(signer *x509.Certificate, cert *x509.Certificate) error {
	if signer == nil {
		return fmt.Errorf("signer certificate is required")
	}
	if cert == nil {
		return fmt.Errorf("fetched certificate is required")
	}
	if !cert.IsCA {
		return fmt.Errorf("fetched certificate is not a CA certificate")
	}
	if len(signer.RawIssuer) > 0 && !bytes.Equal(cert.RawSubject, signer.RawIssuer) {
		return fmt.Errorf("fetched certificate subject does not match signer issuer")
	}
	if len(signer.AuthorityKeyId) > 0 && !bytes.Equal(cert.SubjectKeyId, signer.AuthorityKeyId) {
		return fmt.Errorf("fetched certificate subject key identifier does not match signer authority key identifier")
	}

	return nil
}

// microsoftIntermediateCandidateURLs treats signer AIA values as untrusted
// input. It keeps only entries that stay within the configured Microsoft PKI
// host/path allowlist and normalizes them onto the configured scheme and host.
func microsoftIntermediateCandidateURLs(baseURL string, signer *x509.Certificate) ([]string, error) {
	if signer == nil {
		return nil, fmt.Errorf("signer certificate is required")
	}
	if baseURL == "" {
		return nil, fmt.Errorf("base URL is required")
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parsing base URL: %w", err)
	}
	if !base.IsAbs() || base.Host == "" {
		return nil, fmt.Errorf("base URL must be absolute")
	}

	basePath := path.Clean(strings.TrimRight(base.Path, "/"))
	if basePath == "." || basePath == "/" {
		return nil, fmt.Errorf("base URL path is too broad")
	}

	var urls []string
	seen := make(map[string]struct{})
	for _, rawURL := range signer.IssuingCertificateURL {
		normalized, ok := normalizeMicrosoftIntermediateURL(base, basePath, rawURL)
		if !ok {
			continue
		}
		if _, found := seen[normalized]; found {
			continue
		}
		seen[normalized] = struct{}{}
		urls = append(urls, normalized)
	}

	if len(urls) == 0 {
		return nil, fmt.Errorf("no valid Microsoft PKI AIA URLs found")
	}

	return urls, nil
}

// normalizeMicrosoftIntermediateURL copies only the allowed parts of a signer
// AIA URL onto the configured Microsoft PKI base URL. This keeps the path we
// need while ignoring attacker-controlled scheme, query, fragment, and userinfo.
func normalizeMicrosoftIntermediateURL(base *url.URL, basePath string, rawURL string) (string, bool) {
	if base == nil {
		return "", false
	}

	candidate, err := url.Parse(rawURL)
	if err != nil {
		return "", false
	}
	if candidate.User != nil || candidate.RawQuery != "" || candidate.Fragment != "" {
		return "", false
	}
	if candidate.Scheme != "http" && candidate.Scheme != "https" {
		return "", false
	}
	if !strings.EqualFold(candidate.Hostname(), base.Hostname()) || candidate.Port() != base.Port() {
		return "", false
	}

	candidatePath := path.Clean(candidate.Path)
	if candidatePath != basePath && !strings.HasPrefix(candidatePath, basePath+"/") {
		return "", false
	}

	return (&url.URL{
		Scheme: base.Scheme,
		Host:   base.Host,
		Path:   candidatePath,
	}).String(), true
}

// Azure guidance requires the metadata signer certificate to identify
// metadata.azure.com or a regional *.metadata.azure.com name in its DNS SANs.
func validateAzureMetadataSignerSAN(signer *x509.Certificate) error {
	if signer == nil {
		return fmt.Errorf("signer certificate is required")
	}

	for _, dnsName := range signer.DNSNames {
		if dnsName == azureMetadataDNSName || strings.HasSuffix(dnsName, azureMetadataSubdomainSuffix) {
			return nil
		}
	}

	return fmt.Errorf("signer certificate SAN does not match Azure metadata domains")
}

// verifySignerCertChain verifies that the signer certificate chains to a trusted root CA.
func verifySignerCertChain(signer *x509.Certificate, pkcs7Certs []*x509.Certificate, rootCertPool *x509.CertPool, intermediateCerts *x509.CertPool) error {
	if signer == nil {
		return fmt.Errorf("signer certificate is required")
	}
	if rootCertPool == nil {
		return fmt.Errorf("root certificate pool is required")
	}
	if intermediateCerts == nil {
		return fmt.Errorf("intermediate certificate pool is required")
	}

	intermediates := intermediateCerts.Clone()
	for _, cert := range pkcs7Certs {
		intermediates.AddCert(cert)
	}

	_, err := signer.Verify(x509.VerifyOptions{
		Roots:         rootCertPool,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}
