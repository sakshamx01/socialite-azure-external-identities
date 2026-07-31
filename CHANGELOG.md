# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

