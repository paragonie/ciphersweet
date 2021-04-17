<?php
namespace ParagonIE\CipherSweet\Tests\MultiTenant;

use ParagonIE\CipherSweet\Backend\BoringCrypto;
use ParagonIE\CipherSweet\Backend\FIPSCrypto;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\CompoundIndex;
use ParagonIE\CipherSweet\EncryptedField;
use ParagonIE\CipherSweet\EncryptedRow;
use ParagonIE\CipherSweet\Exception\ArrayKeyException;
use ParagonIE\CipherSweet\Exception\CipherSweetException;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;
use ParagonIE\CipherSweet\Exception\InvalidCiphertextException;
use ParagonIE\CipherSweet\KeyProvider\StringProvider;
use ParagonIE\CipherSweet\Transformation\LastFourDigits;
use PHPUnit\Framework\TestCase;

/**
 * Class MultiTenantTest
 * @package ParagonIE\CipherSweet\Tests\MultiTenant
 */
class MultiTenantTest extends TestCase
{
    /** @var CipherSweet $csBoring */
    private $csBoring;
    /** @var CipherSweet $csFips */
    private $csFips;

    /**
     * @before
     */
    public function before()
    {
        $provider = new TestMultiTenantKeyProvider([
            'foo' => new StringProvider(random_bytes(32)),
            'bar' => new StringProvider(random_bytes(32)),
            'baz' => new StringProvider(random_bytes(32)),
        ]);
        $provider->setActiveTenant('foo');
        $this->csBoring = new CipherSweet($provider, new BoringCrypto());
        $this->csFips = new CipherSweet($provider, new FIPSCrypto());
    }

    protected function getERClass(CipherSweet $cs)
    {
        $ER = new EncryptedRow($cs, 'customer');
        $ER->addTextField('email', 'customerid');
        $ER->addTextField('ssn', 'customerid');
        $ER->addBooleanField('active', 'customerid');
        $ER->addCompoundIndex(
            (new CompoundIndex('customer_ssnlast4_active', ['ssn', 'active'], 15, true))
                ->addTransform('ssn', new LastFourDigits())
        );
        return $ER;
    }

    /**
     * @throws CipherSweetException
     * @throws CryptoOperationException
     * @throws InvalidCiphertextException
     * @throws \SodiumException
     */
    public function testEncryptField()
    {
        foreach ([$this->csBoring, $this->csFips] as $cs) {
            $EF = new EncryptedField($cs, 'table', 'column');
            $EF->setActiveTenant('foo');
            $cipher = $EF->encryptValue('test plaintext', 'aad');
            $plain = $EF->decryptValue($cipher, 'aad');
            $this->assertSame('test plaintext', $plain);

            $EF->setActiveTenant('bar');
            $decryptFailed = false;
            try {
                $EF->decryptValue($cipher, 'aad');
            } catch (\SodiumException $ex) {
                $decryptFailed = true;
            } catch (CipherSweetException $ex) {
                $decryptFailed = true;
            }
            $this->assertTrue($decryptFailed, 'Swapping out tenant identifiers should fail decryption');
        }
    }

    /**
     * Test that the EncryptedRow feature correctly interacts with multi-tenant data stores.
     *
     * @throws CipherSweetException
     * @throws ArrayKeyException
     * @throws CryptoOperationException
     * @throws \SodiumException
     */
    public function testEncryptRow()
    {
        foreach ([$this->csBoring, $this->csFips] as $cs) {
            $ER = $this->getERClass($cs);

            // We encrypt this on behalf of one tenant:
            $cs->setActiveTenant('foo');
            $row1 = $ER->encryptRow([
                'customerid' => 1,
                'email' => 'ciphersweet@paragonie.com',
                'ssn' => '123-45-6789',
                'active' => true
            ]);
            $this->assertSame('foo', $row1['tenant']);
            $plain1 = $ER->decryptRow($row1);
            $this->assertSame('ciphersweet@paragonie.com', $plain1['email']);

            // We encrypt this on behalf of another tenant:
            $cs->setActiveTenant('bar');
            $row2 = $ER->encryptRow([
                'customerid' => 2,
                'email' => 'security@paragonie.com',
                'ssn' => '987-65-4321',
                'active' => true
            ]);
            $this->assertSame('bar', $row2['tenant']);
            $plain2 = $ER->decryptRow($row2);
            $this->assertSame('security@paragonie.com', $plain2['email']);

            // Make a copy, switch the tenant identifier
            $row3 = $row2;
            $row3['tenant'] = 'foo';
            $decryptFailed = false;
            try {
                $ER->decryptRow($row3);
            } catch (\SodiumException $ex) {
                $decryptFailed = true;
            } catch (CipherSweetException $ex) {
                $decryptFailed = true;
            }
            $this->assertTrue($decryptFailed, 'Swapping out tenant identifiers should fail decryption');
        }
    }
}
