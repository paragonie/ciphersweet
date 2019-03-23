<?php
namespace ParagonIE\CipherSweet\Tests;

use ParagonIE\CipherSweet\Backend\FIPSCrypto;
use ParagonIE\CipherSweet\Backend\ModernCrypto;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\EncryptedFile;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;
use ParagonIE\CipherSweet\Exception\FilesystemException;
use ParagonIE\CipherSweet\KeyProvider\StringProvider;
use ParagonIE\ConstantTime\Binary;
use ParagonIE\ConstantTime\Hex;
use PHPUnit\Framework\TestCase;

/**
 * Class EncryptedFileTest
 * @package ParagonIE\CipherSweet\Tests
 */
class EncryptedFileTest extends TestCase
{
    /** @var EncryptedFile $fips */
    private $fips;

    /** @var EncryptedFile $nacl */
    private $nacl;

    /**
     * @throws CryptoOperationException
     */
    public function setUp()
    {
        $this->fips = new EncryptedFile(
            new CipherSweet(
                new StringProvider(
                     Hex::decode(
                        '4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc'
                    )
                ),
                new FIPSCrypto()
            )
        );
        $this->nacl = new EncryptedFile(
            new CipherSweet(
                new StringProvider(
                    Hex::decode(
                        '4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc'
                    )
                ),
                new ModernCrypto()
            )
        );
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
