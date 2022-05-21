<?php
namespace ParagonIE\CipherSweet\Tests\MultiTenant;

use ParagonIE\CipherSweet\Exception\CipherSweetException;
use ParagonIE\CipherSweet\KeyProvider\MultiTenantProvider;
use ParagonIE\ConstantTime\Base64UrlSafe;

/**
 * Class TestMultiTenantKeyProvider
 * @package ParagonIE\CipherSweet\Tests\MultiTenant
 */
class TestMultiTenantKeyProvider extends MultiTenantProvider
{
    /**
     * Given a row of data, determine which tenant should be selected.
     *
     * @param array $row
     * @return string
     *
     * @throws CipherSweetException
     */
    public function getTenantFromRow(array $row, string $tableName): string
    {
        switch ($row['tenant']) {
            case 'foo':
            case 'bar':
            case 'baz':
                return $row['tenant'];
            default:
                return parent::getTenantFromRow($row, $tableName);
        }
    }

    /**
     * @param array $row
     * @param string $tableName
     * @return array
     * @throws CipherSweetException
     */
    public function injectTenantMetadata(array $row, string $tableName): array
    {
        if ($tableName !== 'meta') {
            $row['tenant-extra'] = $tableName;
        } else {
            $row['wrapped-key'] = $this->wrapKey($tableName);
        }
        $row['tenant'] = $this->active;
        return $row;
    }

    /**
     * This is just a dummy key-wrapping example.
     * You'd really want to use KMS from AWS or GCP.
     *
     * @param string $tableName
     * @return string
     * @throws CipherSweetException
     * @throws \SodiumException
     */
    protected function wrapKey(string $tableName = ''): string
    {
        $wrappingKey = sodium_crypto_generichash('unit tests');
        $nonce = random_bytes(24);

        $wrapped = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
            $this->getActiveTenant()->getSymmetricKey()->getRawKey(),
            $tableName,
            $nonce,
            $wrappingKey
        );

        return Base64UrlSafe::encode($nonce . $wrapped);
    }
}
