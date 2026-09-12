# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **JWKS key-rotation retry**: When ID token signature verification fails against the
  cached JWKS (a `JwksSignatureException`), the provider now automatically busts the
  JWKS cache, fetches fresh keys from Microsoft, and retries verification exactly once.
  This makes the package self-heal during Microsoft Entra External ID key-rotation events
  (planned or emergency) without requiring any cache TTL to expire, eliminating what would
  otherwise be a complete authentication outage for up to one hour.
- New `JwksSignatureException` class (extends `TokenValidationException`) to distinguish
  a key-mismatch / unknown-kid failure from other token validation errors. This makes the
  retry logic surgical: only key-rotation scenarios trigger a retry; expired tokens, bad
  nonces, and other errors propagate immediately.
- `OpenIdConfigurationResolver::forgetJwks(string $jwksUri)` — busts the JWKS cache for
  a given URI. Called internally by the retry logic; also available to package consumers
  who need to force a JWKS refresh programmatically.
- `OpenIdConfigurationResolver::forgetConfiguration(string $authority)` — busts the OpenID
  discovery-document cache for a given authority. Provided for symmetry and completeness.

## [1.0.0] - 2026-07-28

### Added

- Initial release of the Microsoft Entra External ID Socialite provider
- Authorization code flow with PKCE, nonce, and state validation
- ID token verification via JWKS
- OpenID configuration and JWKS caching
- Optional user flow / policy support
- Logout URL helper
- Laravel 11 and 12 support

## [1.0.1] - 2026-07-31

### Fixed

- Untype `$usesPKCE` so the provider is compatible with Laravel Socialite 5.29+ (parent property is untyped)

## [1.0.2] - 2026-08-04

### Fixed/added

- Microsoft JWKS keys often omit alg, and JWT 6+/7+ require it.
- PKCE code_verifier + nonce session support added.