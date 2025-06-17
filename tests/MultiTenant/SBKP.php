<?php
namespace ParagonIE\CipherSweet\Tests\MultiTenant;

use ParagonIE\CipherSweet\Contract\StaticBlindIndexKeyProviderInterface;

/**
 * Class TestMultiTenantKeyProvider
 * @package ParagonIE\CipherSweet\Tests\MultiTenant
 */
class SBKP extends TestMultiTenantKeyProvider implements StaticBlindIndexKeyProviderInterface
{
    protected string|int|null $blindIndexTenant = null;

    public function getStaticBlindIndexTenant(): string|int|null
    {
        return $this->blindIndexTenant;
    }

    public function setStaticBlindIndexTenant(int|string|null $tenant = null): void
    {
        $this->blindIndexTenant = $tenant;
    }
}
