<?php
namespace ParagonIE\CipherSweet\Tests;

use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\EncryptedJsonField;
use ParagonIE\CipherSweet\Exception\ArrayKeyException;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;
use ParagonIE\CipherSweet\Exception\InvalidCiphertextException;
use ParagonIE\CipherSweet\Exception\JsonMapException;
use ParagonIE\CipherSweet\JsonFieldMap;
use ParagonIE\ConstantTime\Hex;
use PHPUnit\Framework\TestCase;

/**
 * @psalm-suppress
 */
class EncryptedJsonFieldTest extends TestCase
{
    use CreatesEngines;

    /**
     * @var CipherSweet $fipsEngine
     */
    protected $fipsEngine;

    /**
     * @var CipherSweet $boringEngine
     */
    protected $boringEngine;

    /**
     * @var CipherSweet $fipsRandom
     */
    protected $fipsRandom;

    /**
     * @var CipherSweet $boringRandom
     */
    protected $boringRandom;

    /**
     * @before
     *
     * @throws ArrayKeyException
     * @throws CryptoOperationException
     */
    public function before()
    {
        $this->fipsEngine = $this->createFipsEngine('4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc');
        $this->boringEngine = $this->createBoringEngine('4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc');

        $this->fipsRandom = $this->createFipsEngine();
        $this->boringRandom = $this->createBoringEngine();
    }

    public function engineProvider()
    {
        if (!isset($this->fipsEngine)) {
            $this->before();
        }
        return [
            [$this->fipsEngine],
            [$this->fipsRandom],
            [$this->boringEngine],
            [$this->boringRandom]
        ];
    }

    /**
     * @dataProvider engineProvider
     */
    public function testDeriveKey(CipherSweet $engine)
    {
        $ejf = new EncryptedJsonField(
            $engine->getBackend(),
            $engine->getFieldSymmetricKey('table_name', 'field_name'),
            new JsonFieldMap()
        );

        $key1 = Hex::encode($ejf->deriveKey('$666f6f.$626172')->getRawKey());
        $key2 = Hex::encode($ejf->deriveKey('$626172.$62617a')->getRawKey());
        $this->assertNotSame($key1, $key2);

        $ejf2 = new EncryptedJsonField(
            $engine->getBackend(),
            $engine->getFieldSymmetricKey('table_name', 'different_field'),
            new JsonFieldMap()
        );

        $key3 = Hex::encode($ejf2->deriveKey('$666f6f.$626172')->getRawKey());
        $key4 = Hex::encode($ejf2->deriveKey('$626172.$62617a')->getRawKey());
        $this->assertNotSame($key3, $key4);

        $this->assertNotSame($key1, $key3);
        $this->assertNotSame($key2, $key4);
    }

    /**
     * @dataProvider engineProvider
     *
     * @throws JsonMapException
     */
    public function testFieldEncryption(CipherSweet $engine)
    {
        $map = (new JsonFieldMap())
            ->addTextField(['name'])
            ->addBooleanField(['active'])
            ->addIntegerField(['age'])
            ->addFloatField(['latitude'])
            ->addFloatField(['longitude']);

        $ejf = new EncryptedJsonField(
            $engine->getBackend(),
            $engine->getKeyProvider()->getSymmetricKey(),
            $map
        );

        $plaintext = [
            'id' => 12345,
            'name' => 'foo',
            'active' => (random_int(0, 1) === 1),
            'age' => random_int(18,100),
            'latitude' => 37.2431,
            'longitude' => 115.7930
        ];
        $encrypted = $ejf->encryptJson($plaintext);

        $encArray = json_decode($encrypted, true);
        $prefix = $engine->getBackend()->getPrefix();

        $this->assertStringStartsNotWith($prefix, $encArray['id'], 'id should not be encrypted');
        $this->assertStringStartsWith($prefix, $encArray['name'], 'field "name" should be encrypted');
        $this->assertStringStartsWith($prefix, $encArray['active'], 'field "active" should be encrypted');
        $this->assertStringStartsWith($prefix, $encArray['age'], 'field "age" should be encrypted');
        $this->assertStringStartsWith($prefix, $encArray['latitude'], 'field "latitude" should be encrypted');
        $this->assertStringStartsWith($prefix, $encArray['longitude'], 'field "longitude" should be encrypted');

        $decrypted = $ejf->decryptJson($encrypted);

        $this->assertEquals($plaintext['name'], $decrypted['name']);
        $this->assertEquals($plaintext['active'], $decrypted['active']);
        $this->assertEquals($plaintext['age'], $decrypted['age']);
        $this->assertEqualsWithDelta($plaintext['latitude'], $decrypted['latitude'], 0.00000001);
        $this->assertEqualsWithDelta($plaintext['longitude'], $decrypted['longitude'], 0.00000001);
    }

    /**
     * @dataProvider engineProvider
     *
     * @throws JsonMapException
     */
    public function testUnhappyPath(CipherSweet $engine)
    {
        $map = (new JsonFieldMap())
            ->addTextField(['name'])
            ->addBooleanField(['active'])
            ->addIntegerField(['age'])
            ->addFloatField(['latitude'])
            ->addFloatField(['longitude']);

        $ejf = new EncryptedJsonField(
            $engine->getBackend(),
            $engine->getKeyProvider()->getSymmetricKey(),
            $map
        );

        $plaintext = [
            'id' => 12345,
            'name' => 'foo',
            'active' => (random_int(0, 1) === 1),
            'age' => random_int(18,100),
            'latitude' => 37.2431,
            'longitude' => 115.7930
        ];
        $encrypted = $ejf->encryptJson($plaintext);

        $encArray = json_decode($encrypted, true);
        $copy = $encArray;

        // Let's swap two fields
        $copy['active'] = $encArray['age'];
        $copy['age'] = $encArray['active'];

        // Attempt decryption
        $this->expectException(InvalidCiphertextException::class);
        $ejf->decryptJson(json_encode($copy));

        $this->fail("Expected exception was not thrown");
    }
}
