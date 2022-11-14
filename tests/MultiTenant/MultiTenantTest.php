<?php
namespace ParagonIE\CipherSweet\Tests\MultiTenant;

use ParagonIE\CipherSweet\Backend\BoringCrypto;
use ParagonIE\CipherSweet\Backend\FIPSCrypto;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\CompoundIndex;
use ParagonIE\CipherSweet\EncryptedField;
use ParagonIE\CipherSweet\EncryptedFile;
use ParagonIE\CipherSweet\EncryptedMultiRows;
use ParagonIE\CipherSweet\EncryptedRow;
use ParagonIE\CipherSweet\Exception\ArrayKeyException;
use ParagonIE\CipherSweet\Exception\CipherSweetException;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;
use ParagonIE\CipherSweet\Exception\InvalidCiphertextException;
use ParagonIE\CipherSweet\KeyProvider\StringProvider;
use ParagonIE\CipherSweet\Transformation\LastFourDigits;
use ParagonIE\ConstantTime\Base32;
use ParagonIE\ConstantTime\Hex;
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

    /**
     * @param CipherSweet $cs
     * @return EncryptedRow
     */
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
     * @param CipherSweet $cs
     * @return EncryptedMultiRows
     * @throws CipherSweetException
     */
    protected function getMultiRows(CipherSweet $cs)
    {
        $EMR = new EncryptedMultiRows($cs);
        $EMR->addTable('meta');
        $EMR->addTextField('meta', 'data');
        $EMR->addTable('customer');
        $EMR->addTextField('customer', 'email', 'customerid');
        $EMR->addTextField('customer', 'ssn', 'customerid');
        $EMR->addBooleanField('customer', 'active', 'customerid');
        $EMR->addCompoundIndex(
            'customer',
            (new CompoundIndex('customer_ssnlast4_active', ['ssn', 'active'], 15, true))
                ->addTransform('ssn', new LastFourDigits())
        );
        $EMR->addTable('customer_secret');
        $EMR->addTextField('customer_secret', '2fa');
        $EMR->addTextField('customer_secret', 'pwhash');
        return $EMR;
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

    public function testEncryptedFile()
    {
        $message = "Paragon Initiative Enterprises\n" . \random_bytes(256);

        foreach ([$this->csBoring, $this->csFips] as $cs) {
            $fileCrypto = new EncryptedFile($cs);
            $fileCrypto->setActiveTenant('foo');

            $input = $fileCrypto->getStreamForFile('php://temp');
            $output = $fileCrypto->getStreamForFile('php://temp');
            $decrypted = $fileCrypto->getStreamForFile('php://temp');
            \fwrite($input, $message);
            \fseek($input, 0, SEEK_SET);

            // Encrypt the stream
            $fileCrypto->encryptStream($input, $output);

            \fseek($output, 0, SEEK_SET);

            // Decrypt the stream
            $fileCrypto->decryptStream($output, $decrypted);

            \fseek($input, 0, SEEK_SET);
            \fseek($output, 0, SEEK_SET);
            \fseek($decrypted, 0, SEEK_SET);
            // We should get the same plaintext
            $this->assertSame(
                Hex::encode(\stream_get_contents($input)),
                Hex::encode(\stream_get_contents($decrypted))
            );

            // Now let's change the active tenant
            $fileCrypto->setActiveTenant('bar');
            \fseek($output, 0, SEEK_SET);

            // We should get a decryption error with the wrong tenant
            $decrypted2 = $fileCrypto->getStreamForFile('php://temp');
            try {
                $fileCrypto->decryptStream($output, $decrypted2);
                $this->fail("Switching active tenant should cause decryption failure");
            } catch (CipherSweetException $ex) {
                $this->assertSame('Invalid authentication tag', $ex->getMessage());
            }
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
            $this->assertArrayHasKey('tenant-extra', $plain1);

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
            $this->assertArrayHasKey('tenant-extra', $plain2);

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

    /**
     * @throws ArrayKeyException
     * @throws CipherSweetException
     * @throws CryptoOperationException
     * @throws \SodiumException
     */
    public function testEncryptedMultiRows()
    {
        foreach ([$this->csBoring, $this->csFips] as $cs) {
            $EMR = $this->getMultiRows($cs);
            $many1 = $EMR->encryptManyRows(
                [
                    'meta' => ['data' => 'foo'],
                    'customer' => [
                        'customerid' => 1,
                        'email' => 'ciphersweet@paragonie.com',
                        'ssn' => '123-45-6789',
                        'active' => true
                    ],
                    'customer_secret' => [
                        '2fa' => Base32::encode(random_bytes(20)),
                        'pwhash' => '$2y$10$s6gTREuS3dIOpiudUm6K/u0Wu3PoM1gZyr9sA9hAuu/hGiwO8agDa'
                    ]
                ]
            );
            $this->assertArrayHasKey('wrapped-key', $many1['meta']);
            $this->assertArrayNotHasKey('tenant-extra', $many1['meta']);
            $this->assertArrayHasKey('tenant-extra', $many1['customer']);
            $this->assertArrayHasKey('tenant-extra', $many1['customer_secret']);
            $decrypt1 = $EMR->decryptManyRows($many1);
            $this->assertSame('ciphersweet@paragonie.com', $decrypt1['customer']['email']);

            // We encrypt this on behalf of another tenant:
            $cs->setActiveTenant('bar');
            $many2 = $EMR->encryptManyRows(
                [
                    'meta' => ['data' => 'foo'],
                    'customer' => [
                        'customerid' => 2,
                        'email' => 'security@paragonie.com',
                        'ssn' => '987-65-4321',
                        'active' => true
                    ],
                    'customer_secret' => [
                        '2fa' => Base32::encode(random_bytes(20)),
                        'pwhash' => '$2y$10$Tvk8Uo338tK2AoqIwCnwiOV5tIKwGM/r93MzXbX.h/0iFYhpuRn3W'
                    ]
                ]
            );
            $this->assertArrayHasKey('wrapped-key', $many2['meta']);
            $this->assertArrayNotHasKey('tenant-extra', $many2['meta']);
            $this->assertArrayHasKey('tenant-extra', $many2['customer']);
            $this->assertArrayHasKey('tenant-extra', $many2['customer_secret']);
            $decrypt2 = $EMR->decryptManyRows($many2);
            $this->assertSame('security@paragonie.com', $decrypt2['customer']['email']);


            // Make a copy, switch the tenant identifier
            $many3 = $many2;
            foreach($many3 as $k => $row) {
                $many3[$k]['tenant'] = 'foo';
            }
            $decryptFailed = false;
            try {
                $EMR->decryptManyRows($many3);
            } catch (\SodiumException $ex) {
                $decryptFailed = true;
            } catch (CipherSweetException $ex) {
                $decryptFailed = true;
            }
            $this->assertTrue($decryptFailed, 'Swapping out tenant identifiers should fail decryption');
        }
    }
}
