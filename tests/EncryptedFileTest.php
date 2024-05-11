<?php
namespace ParagonIE\CipherSweet\Tests;

use ParagonIE\CipherSweet\AAD;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\EncryptedFile;
use ParagonIE\CipherSweet\Exception\CipherSweetException;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;
use ParagonIE\CipherSweet\Exception\FilesystemException;
use ParagonIE\ConstantTime\Binary;
use ParagonIE\ConstantTime\Hex;
use PHPUnit\Framework\TestCase;

/**
 * Class EncryptedFileTest
 * @package ParagonIE\CipherSweet\Tests
 */
class EncryptedFileTest extends TestCase
{
    use CreatesEngines;

    /** @var EncryptedFile $brng */
    private $brng;

    /** @var EncryptedFile $fips */
    private $fips;

    /** @var EncryptedFile $nacl */
    private $nacl;

    /**
     * @before
     * @throws CryptoOperationException
     */
    public function before()
    {
        $this->fips = new EncryptedFile(
            $this->createFipsEngine('4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc')
        );

        $this->nacl = new EncryptedFile(
            $this->createModernEngine('4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc')
        );

        $this->brng = new EncryptedFile(
            $this->createBoringEngine('4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc')
        );
    }

    /**
     * @afterClass
     */
    public function afterClass()
    {
        if (file_exists(__DIR__ . '/scratch.txt')) {
            unlink(__DIR__ . '/scratch.txt');
        }
    }

    /**
     * @throws CryptoOperationException
     * @throws FilesystemException
     * @throws \SodiumException
     */
    public function testFipsEncryptStream()
    {
        $message = "Paragon Initiative Enterprises\n" . \random_bytes(256);

        $input = $this->fips->getStreamForFile('php://temp');
        \fwrite($input, $message);
        $this->assertFalse($this->fips->isStreamEncrypted($input));

        $output = $this->fips->getStreamForFile('php://temp');
        $this->fips->encryptStream($input, $output);
        $this->assertTrue($this->fips->isStreamEncrypted($output));

        \fseek($output, 0, SEEK_SET);
        $header = \fread($output, 5);
        \fseek($output, 0, SEEK_SET);

        $this->assertSame(
            $this->fips->getEngine()->getBackend()->getPrefix(),
            $header,
            'Encrypted stream does not have the correct header'
        );

        $decrypted = $this->fips->getStreamForFile('php://temp');
        $this->fips->decryptStream($output, $decrypted);
        $this->assertFalse($this->fips->isStreamEncrypted($decrypted));

        \fseek($input, 0, SEEK_SET);
        \fseek($decrypted, 0, SEEK_SET);

        $this->assertSame(
            Hex::encode(\stream_get_contents($input)),
            Hex::encode(\stream_get_contents($decrypted))
        );
    }

    /**
     * @throws CryptoOperationException
     * @throws FilesystemException
     * @throws \SodiumException
     */
    public function testFipsPasswordEncryptStream()
    {
        $message = "Paragon Initiative Enterprises\n" . \random_bytes(256);
        $password = 'correct horse battery staple';

        $input = $this->fips->getStreamForFile('php://temp');
        \fwrite($input, $message);
        $this->assertFalse($this->fips->isStreamEncrypted($input));

        $output = $this->fips->getStreamForFile('php://temp');
        $this->fips->encryptStreamWithPassword($input, $output, $password);
        $this->assertTrue($this->fips->isStreamEncrypted($output));

        \fseek($output, 0, SEEK_SET);
        $header = \fread($output, 5);
        \fseek($output, 0, SEEK_SET);

        $this->assertSame(
            $this->fips->getEngine()->getBackend()->getPrefix(),
            $header,
            'Encrypted stream does not have the correct header'
        );

        $decrypted = $this->fips->getStreamForFile('php://temp');
        $this->fips->decryptStreamWithPassword($output, $decrypted, $password);
        $this->assertFalse($this->fips->isStreamEncrypted($decrypted));

        \fseek($input, 0, SEEK_SET);
        \fseek($decrypted, 0, SEEK_SET);

        $this->assertSame(
            Hex::encode(\stream_get_contents($input)),
            Hex::encode(\stream_get_contents($decrypted))
        );
    }

    /**
     * @throws CryptoOperationException
     * @throws FilesystemException
     * @throws \SodiumException
     */
    public function testModernEncryptStream()
    {
        $message = "Paragon Initiative Enterprises\n" . \random_bytes(256);

        $input = $this->nacl->getStreamForFile('php://temp');
        \fwrite($input, $message);
        $this->assertFalse($this->nacl->isStreamEncrypted($input));

        $output = $this->nacl->getStreamForFile('php://temp');
        $this->nacl->encryptStream($input, $output);
        $this->assertTrue($this->nacl->isStreamEncrypted($output));

        \fseek($output, 0, SEEK_SET);
        $header = \fread($output, 5);
        \fseek($output, 0, SEEK_SET);

        $this->assertSame(
            $this->nacl->getEngine()->getBackend()->getPrefix(),
            $header,
            'Encrypted stream does not have the correct header'
        );

        $decrypted = $this->nacl->getStreamForFile('php://temp');
        $this->nacl->decryptStream($output, $decrypted);
        $this->assertFalse($this->nacl->isStreamEncrypted($decrypted));

        \fseek($input, 0, SEEK_SET);
        \fseek($decrypted, 0, SEEK_SET);

        $this->assertSame(
            Hex::encode(\stream_get_contents($input)),
            Hex::encode(\stream_get_contents($decrypted))
        );
    }

    /**
     * @throws CryptoOperationException
     * @throws FilesystemException
     * @throws \SodiumException
     */
    public function testModernPasswordEncryptStream()
    {
        if (!\ParagonIE_Sodium_Compat::crypto_pwhash_is_available()) {
            // We cannot
            $this->markTestSkipped('Cannot test this without libsodium');
            return;
        }
        $message = "Paragon Initiative Enterprises\n" . \random_bytes(256);
        $password = 'correct horse battery staple';

        $input = $this->nacl->getStreamForFile('php://temp');
        \fwrite($input, $message);
        $this->assertFalse($this->nacl->isStreamEncrypted($input));

        $output = $this->nacl->getStreamForFile('php://temp');
        $this->nacl->encryptStreamWithPassword($input, $output, $password);
        $this->assertTrue($this->nacl->isStreamEncrypted($output));

        \fseek($output, 0, SEEK_SET);
        $header = \fread($output, 5);
        \fseek($output, 0, SEEK_SET);

        $this->assertSame(
            $this->nacl->getEngine()->getBackend()->getPrefix(),
            $header,
            'Encrypted stream does not have the correct header'
        );

        $decrypted = $this->nacl->getStreamForFile('php://temp');
        $this->nacl->decryptStreamWithPassword($output, $decrypted, $password);
        $this->assertFalse($this->nacl->isStreamEncrypted($decrypted));

        \fseek($input, 0, SEEK_SET);
        \fseek($decrypted, 0, SEEK_SET);

        $this->assertSame(
            Hex::encode(\stream_get_contents($input)),
            Hex::encode(\stream_get_contents($decrypted))
        );
    }

    /**
     * @throws CryptoOperationException
     * @throws FilesystemException
     * @throws \SodiumException
     */
    public function testBoringEncryptStream()
    {
        $message = "Paragon Initiative Enterprises\n" . \random_bytes(256);

        $input = $this->brng->getStreamForFile('php://temp');
        \fwrite($input, $message);
        $this->assertFalse($this->brng->isStreamEncrypted($input));

        $output = $this->brng->getStreamForFile('php://temp');
        $this->brng->encryptStream($input, $output);
        $this->assertTrue($this->brng->isStreamEncrypted($output));

        \fseek($output, 0, SEEK_SET);
        $header = \fread($output, 5);
        \fseek($output, 0, SEEK_SET);

        $this->assertSame(
            $this->brng->getEngine()->getBackend()->getPrefix(),
            $header,
            'Encrypted stream does not have the correct header'
        );

        $decrypted = $this->brng->getStreamForFile('php://temp');
        $this->brng->decryptStream($output, $decrypted);
        $this->assertFalse($this->brng->isStreamEncrypted($decrypted));

        \fseek($input, 0, SEEK_SET);
        \fseek($decrypted, 0, SEEK_SET);

        $this->assertSame(
            Hex::encode(\stream_get_contents($input)),
            Hex::encode(\stream_get_contents($decrypted))
        );
    }

    /**
     * @throws CryptoOperationException
     * @throws FilesystemException
     * @throws \SodiumException
     */
    public function testBoringPasswordEncryptStream()
    {
        if (!\ParagonIE_Sodium_Compat::crypto_pwhash_is_available()) {
            // We cannot
            $this->markTestSkipped('Cannot test this without libsodium');
            return;
        }
        $message = "Paragon Initiative Enterprises\n" . \random_bytes(256);
        $password = 'correct horse battery staple';

        $input = $this->brng->getStreamForFile('php://temp');
        \fwrite($input, $message);
        $this->assertFalse($this->brng->isStreamEncrypted($input));

        $output = $this->brng->getStreamForFile('php://temp');
        $this->brng->encryptStreamWithPassword($input, $output, $password);
        $this->assertTrue($this->brng->isStreamEncrypted($output));

        \fseek($output, 0, SEEK_SET);
        $header = \fread($output, 5);
        \fseek($output, 0, SEEK_SET);

        $this->assertSame(
            $this->brng->getEngine()->getBackend()->getPrefix(),
            $header,
            'Encrypted stream does not have the correct header'
        );

        $decrypted = $this->brng->getStreamForFile('php://temp');
        $this->brng->decryptStreamWithPassword($output, $decrypted, $password);
        $this->assertFalse($this->brng->isStreamEncrypted($decrypted));

        \fseek($input, 0, SEEK_SET);
        \fseek($decrypted, 0, SEEK_SET);

        $this->assertSame(
            Hex::encode(\stream_get_contents($input)),
            Hex::encode(\stream_get_contents($decrypted))
        );
    }

    public function encryptedFileProvider(): array
    {
        if (!$this->brng) {
            $this->before();
        }
        return [
            [$this->brng],
            [$this->fips],
            [$this->nacl],
        ];
    }

    /**
     * @dataProvider encryptedFileProvider
     */
    public function testEncryptedFileWithAAD(EncryptedFile $encFile): void
    {
        $message = "Paragon Initiative Enterprises\n" . \random_bytes(256);

        $input = $encFile->getStreamForFile('php://temp');
        \fwrite($input, $message);
        $this->assertFalse($encFile->isStreamEncrypted($input));
        $aad = AAD::literal('unit testing');

        $output = $encFile->getStreamForFile('php://temp');
        $encFile->encryptStream($input, $output, $aad);
        $this->assertTrue($encFile->isStreamEncrypted($output));

        $dummy1 = $encFile->getStreamForFile('php://temp');
        $encFile->decryptStream($output, $dummy1, $aad);
        $contents = stream_get_contents($dummy1);
        $this->assertSame($message, $contents, 'Sanity check on encryption');

        try {
            $dummy2 = $encFile->getStreamForFile('php://temp');
            $encFile->decryptStream($output, $dummy2);
            $this->fail('Decryption with wrong AAD should fail!');
        } catch (CipherSweetException|\SodiumException) {
        }
    }

    /**
     * @throws CryptoOperationException
     * @throws FilesystemException
     */
    public function testEncryptedSameFile()
    {
        $path = __DIR__ . '/scratch.txt';
        $message = "Paragon Initiative Enterprises\n" . \random_bytes(256);
        \file_put_contents($path, $message);

        $this->fips->encryptFile($path, $path);
        $contents = \file_get_contents($path);
        $this->assertSame(
            Binary::safeSubstr($contents, 0, 5),
            $this->fips->getEngine()->getBackend()->getPrefix()
        );
        $this->fips->decryptFile($path, $path);
        $this->assertSame($message, \file_get_contents($path));

        $this->nacl->encryptFile($path, $path);
        $contents = \file_get_contents($path);
        $this->assertSame(
            Binary::safeSubstr($contents, 0, 5),
            $this->nacl->getEngine()->getBackend()->getPrefix()
        );
        $this->nacl->decryptFile($path, $path);
        $this->assertSame($message, \file_get_contents($path));

        $this->brng->encryptFile($path, $path);
        $contents = \file_get_contents($path);
        $this->assertSame(
            Binary::safeSubstr($contents, 0, 5),
            $this->brng->getEngine()->getBackend()->getPrefix()
        );
        $this->brng->decryptFile($path, $path);
        $this->assertSame($message, \file_get_contents($path));

        $password = 'correct horse battery staple';

        $this->fips->encryptFileWithPassword($path, $path, $password);
        $this->fips->decryptFileWithPassword($path, $path, $password);
        $this->assertSame($message, \file_get_contents($path));

        if (\ParagonIE_Sodium_Compat::crypto_pwhash_is_available()) {
            $this->nacl->encryptFileWithPassword($path, $path, $password);
            $this->nacl->decryptFileWithPassword($path, $path, $password);
            $this->assertSame($message, \file_get_contents($path));
        }
    }
}
