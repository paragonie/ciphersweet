<?php
namespace ParagonIE\CipherSweet\Tests\MultiTenant;

use ParagonIE\CipherSweet\Contract\KeyProviderInterface;
use ParagonIE\CipherSweet\Contract\MultiTenantAwareProviderInterface;
use ParagonIE\CipherSweet\Exception\CipherSweetException;
use ParagonIE\CipherSweet\KeyProvider\MultiTenantProvider;

/**
 * Class TestMultiTenantKeyProvider
 * @package ParagonIE\CipherSweet\Tests\MultiTenant
 */
class TestMultiTenantKeyProvider extends MultiTenantProvider
{
    public function __construct(array $keyProviders, $active = null)
    {
        parent::__construct($keyProviders, $active);
    }

    /**
     * Given a row of data, determine which tenant should be selected.
     *
     * @param array $row
     * @return string
     *
     * @throws CipherSweetException
     */
    public function getTenantFromRow(array $row)
    {
        switch ($row['tenant']) {
            case 'foo':
            case 'bar':
            case 'baz':
                return $row['tenant'];
            default:
                return parent::getTenantFromRow($row);
        }
    }

    /**
     * @param array $row
     * @return array
     * @throws CipherSweetException
     */
    public function injectTenantMetadata(array $row)
    {
        $row['tenant'] = $this->active;
        return $row;
    }
}
