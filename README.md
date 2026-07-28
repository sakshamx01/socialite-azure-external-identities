# Azure External Identities Provider for Laravel Socialite

[![Latest Version on Packagist](https://img.shields.io/packagist/v/zulficarjoy/socialite-azure-external-identities.svg?style=flat-square)](https://packagist.org/packages/zulficarjoy/socialite-azure-external-identities)
[![Total Downloads](https://img.shields.io/packagist/dt/zulficarjoy/socialite-azure-external-identities.svg?style=flat-square)](https://packagist.org/packages/zulficarjoy/socialite-azure-external-identities)
[![License](https://img.shields.io/packagist/l/zulficarjoy/socialite-azure-external-identities.svg?style=flat-square)](LICENSE)

A Laravel Socialite provider for [Microsoft Entra External ID](https://learn.microsoft.com/en-us/entra/external-id/customers/) (formerly Azure AD B2C successor for customer identity). Authenticate external users against your CIAM tenant using the standard OAuth 2.0 authorization code flow with PKCE.

## Features

- Built for **Microsoft Entra External ID** (`.ciamlogin.com`) tenants
- OpenID Connect authorization code flow with **PKCE** enabled by default
- **ID token validation** via JWKS with configurable verification
- **Nonce** validation to mitigate replay attacks
- Optional **user flow / policy** support via the `p` parameter
- **Logout URL** helper for single sign-out
- Compatible with **Laravel 11 and 12**
- Works with [SocialiteProviders Manager](https://socialiteproviders.com/)

## Requirements

- PHP 8.2+
- Laravel 11 or 12
- A Microsoft Entra External ID (CIAM) tenant with a registered application

## Installation

```bash
composer require zulficarjoy/socialite-azure-external-identities
```

Follow the [SocialiteProviders base installation guide](https://socialiteproviders.com/usage/) if you have not set up SocialiteProviders Manager yet.

### Register the provider

#### Laravel 11+

Add the listener in `AppServiceProvider::boot()`:

```php
use Illuminate\Support\Facades\Event;
use SocialiteProviders\AzureExternalIdentities\Provider;
use SocialiteProviders\Manager\SocialiteWasCalled;

Event::listen(function (SocialiteWasCalled $event) {
    $event->extendSocialite('azure-ei', Provider::class);
});
```

#### Laravel 10 and below

Add the listener to `app/Providers/EventServiceProvider.php`:

```php
protected $listen = [
    \SocialiteProviders\Manager\SocialiteWasCalled::class => [
        \SocialiteProviders\AzureExternalIdentities\AzureExternalIdentitiesExtendSocialite::class.'@handle',
    ],
];
```

> **Note:** If you use Composer's SocialiteProviders auto-discovery, the listener may be registered automatically via the package's `composer.json` extra configuration.

## Configuration

Add the following to `config/services.php`:

```php
'azure-ei' => [
    'client_id' => env('AZURE_EI_CLIENT_ID'),
    'client_secret' => env('AZURE_EI_CLIENT_SECRET'),
    'redirect' => env('AZURE_EI_REDIRECT_URI'),

    // Required unless `authority` is set
    'tenant_subdomain' => env('AZURE_EI_TENANT_SUBDOMAIN'),
    'tenant_id' => env('AZURE_EI_TENANT_ID'),

    // Optional: override the full authority URL
    // 'authority' => 'https://contoso.ciamlogin.com/00000000-0000-0000-0000-000000000000/v2.0',

    // Optional: user flow / policy name (passed as the `p` parameter)
    // 'policy' => env('AZURE_EI_POLICY'),

    // Optional: verify ID token signature via JWKS (default: true)
    'verify_id_token' => env('AZURE_EI_VERIFY_ID_TOKEN', true),

    // Optional: HTTP proxy for outbound requests
    // 'proxy' => env('AZURE_EI_PROXY'),
],
```

### Environment variables

```dotenv
AZURE_EI_CLIENT_ID=your-application-client-id
AZURE_EI_CLIENT_SECRET=your-client-secret
AZURE_EI_REDIRECT_URI="${APP_URL}/auth/azure-ei/callback"
AZURE_EI_TENANT_SUBDOMAIN=contoso
AZURE_EI_TENANT_ID=00000000-0000-0000-0000-000000000000
# AZURE_EI_POLICY=B2X_1_signupsignin
# AZURE_EI_VERIFY_ID_TOKEN=true
```

### Finding your tenant values

| Value | Where to find it |
|-------|------------------|
| `tenant_subdomain` | Your CIAM domain prefix, e.g. `contoso` from `contoso.ciamlogin.com` |
| `tenant_id` | Microsoft Entra admin center → External tenant → Overview → Tenant ID |
| `client_id` | App registration → Application (client) ID |
| `client_secret` | App registration → Certificates & secrets |

The provider builds the authority URL as:

```
https://{tenant_subdomain}.ciamlogin.com/{tenant_id}/v2.0
```

Alternatively, set `authority` directly if you need a custom configuration.

## Usage

### Redirect to sign-in

```php
use Laravel\Socialite\Facades\Socialite;

Route::get('/login/azure-ei', function () {
    return Socialite::driver('azure-ei')->redirect();
});
```

### Handle the callback

```php
Route::get('/auth/azure-ei/callback', function () {
    $azureUser = Socialite::driver('azure-ei')->user();

    // $azureUser->getId()       — object ID (oid) or subject (sub)
    // $azureUser->getEmail()    — email address
    // $azureUser->getName()     — display name
    // $azureUser->token         — access token
    // $azureUser->refreshToken  — refresh token (if offline_access granted)
    // $azureUser->user          — raw token claims
});
```

### Custom scopes

```php
return Socialite::driver('azure-ei')
    ->scopes(['openid', 'profile', 'email'])
    ->redirect();
```

### Stateless authentication

Useful for API-only flows:

```php
$user = Socialite::driver('azure-ei')
    ->stateless()
    ->user();
```

### Logout

Sign the user out of your application and redirect to Microsoft Entra External ID logout:

```php
Auth::logout();
request()->session()->invalidate();
request()->session()->regenerateToken();

$logoutUrl = Socialite::driver('azure-ei')
    ->getLogoutUrl(route('login'));

return redirect($logoutUrl);
```

## Security

This provider enables several security measures by default:

| Feature | Default | Description |
|---------|---------|-------------|
| PKCE | Enabled | Protects the authorization code exchange |
| Nonce | Enabled | Binds the ID token to the authentication request |
| ID token verification | Enabled | Validates signature, audience, and expiry via JWKS |
| State parameter | Enabled | Inherited from Socialite; prevents CSRF on callback |

OpenID configuration and JWKS documents are cached for one hour to reduce latency.

To disable ID token signature verification (not recommended for production):

```php
'verify_id_token' => false,
```

## Mapped user attributes

| Socialite field | Token claim |
|-----------------|-------------|
| `id` | `oid` or `sub` |
| `email` | `email`, `emails[]`, or `preferred_username` |
| `name` | `name` |
| `nickname` | `preferred_username` |
| `given_name` | `given_name` |
| `family_name` | `family_name` |
| `tenant_id` | `tid` |

## Contributing

Contributions are welcome. Please open an issue or pull request on [GitHub](https://github.com/zulficarjoy/socialite-azure-external-identities).

## License

The MIT License (MIT). Copyright (c) 2026 Zulficar Hasan Joy. See [LICENSE](LICENSE) for details.

## Credits

- [Zulficar Hasan Joy](https://github.com/zulficarjoy)
- [Laravel Socialite](https://github.com/laravel/socialite)
- [SocialiteProviders Manager](https://github.com/SocialiteProviders/Manager)
