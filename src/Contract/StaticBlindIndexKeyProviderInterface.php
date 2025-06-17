<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\Contract;

/**
 * Enables Key Providers to enable/disable using a specific, static "Tenant" for deriving the root keys
 * for Blind Indexes and Compound Indexes.
 */
interface StaticBlindIndexKeyProviderInterface extends MultiTenantAwareProviderInterface
{
    public function getStaticBlindIndexTenant(): string|int|null;
    public function setStaticBlindIndexTenant(string|int|null $tenant = null): void;
}
