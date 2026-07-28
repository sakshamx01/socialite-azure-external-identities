<?php

namespace SocialiteProviders\AzureExternalIdentities;

use SocialiteProviders\Manager\SocialiteWasCalled;

class AzureExternalIdentitiesExtendSocialite
{
    public function handle(SocialiteWasCalled $socialiteWasCalled): void
    {
        $socialiteWasCalled->extendSocialite('azure-ei', Provider::class);
    }
}
