<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\Tests;

use ParagonIE\CipherSweet\Backend\{
    BoringCrypto,
    FIPSCrypto,
    ModernCrypto
};
use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\EncryptedFile;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionException;

#[CoversClass(EncryptedFile::class)]
class FileChunkSizeTest extends TestCase
{
    private static function stream(string $data = '')
    {
        $fp = fopen('php://temp', 'w+b');
        fwrite($fp, $data);
        rewind($fp);
        return $fp;
    }

    public function testCrossChunkSizes(): void
    {
        $key = new SymmetricKey(str_repeat('K', 32));
        foreach ([new BoringCrypto(), new FIPSCrypto(), new ModernCrypto()] as $backend) {
            foreach ([0, 1, 15, 16, 17, 63, 64, 65, 129, 8193] as $length) {
                $message = substr(str_repeat("0123456789abcdef\0", 483), 0, $length);
                foreach ([1, 15, 16, 63, 64, 65, 8192] as $writeSize) {
                    $input = self::stream($message);
                    $cipher = self::stream();
                    try {
                        $backend->doStreamEncrypt($input, $cipher, $key, $writeSize);
                        $this->assertSame($backend::STREAM_HEADER, fread($cipher, 5));
                        foreach ([1, 17, 64, 65, 8192] as $readSize) {
                            $output = self::stream();
                            try {
                                $backend->doStreamDecrypt($cipher, $output, $key, $readSize);
                                $this->assertSame($message, stream_get_contents($output),
                                    get_class($backend) . ": $length/$writeSize/$readSize");
                            } finally {
                                fclose($output);
                            }
                        }
                    } finally {
                        fclose($input);
                        fclose($cipher);
                    }
                }
            }
        }
    }

    /**
     * @throws ReflectionException
     */
    public function testLegacyFiles(): void
    {
        $fixtures = json_decode(
            file_get_contents(__DIR__ . '/KnownAnswers/legacy-file-chunks.json'),
            true
        );
        $key = new SymmetricKey(str_repeat('K', 32));
        foreach ([new BoringCrypto(), new FIPSCrypto(), new ModernCrypto()] as $backend) {
            $name = (new ReflectionClass($backend))->getShortName();
            foreach ([64, 65] as $writerSize) {
                foreach ($writerSize === 64 ? [64, 8192] : [65] as $readerSize) {
                    $input = self::stream(base64_decode($fixtures[$name][$writerSize]));
                    $output = self::stream();
                    try {
                        $backend->doStreamDecrypt($input, $output, $key, $readerSize);
                        $this->assertSame(str_repeat('A', 200), stream_get_contents($output));
                    } finally {
                        fclose($input);
                        fclose($output);
                    }
                }
            }
        }
    }


    public function testShortReads(): void
    {
        stream_wrapper_register('ciphersweetshort', ShortReadStream::class);
        $key = new SymmetricKey(str_repeat('K', 32));
        $message = str_repeat('0123456789', 30);
        try {
            foreach ([new BoringCrypto(), new FIPSCrypto(), new ModernCrypto()] as $backend) {
                ShortReadStream::$data = $message;
                ShortReadStream::$headerLength = 0;
                $input = fopen('ciphersweetshort://input', 'rb');
                $cipher = self::stream();
                $output = self::stream();
                try {
                    $backend->doStreamEncrypt($input, $cipher, $key, 65);
                    $backend->doStreamDecrypt($cipher, $output, $key, 64);
                    $this->assertSame($message, stream_get_contents($output));

                    rewind($cipher);
                    ShortReadStream::$data = stream_get_contents($cipher);
                    ShortReadStream::$headerLength = $backend instanceof FIPSCrypto ? 117
                        : ($backend instanceof BoringCrypto ? 77 : 61);
                    $shortCipher = fopen('ciphersweetshort://input', 'rb');
                    try {
                        $backend->doStreamDecrypt($shortCipher, $output, $key, 65);
                        $this->assertSame($message, stream_get_contents($output));
                    } finally {
                        fclose($shortCipher);
                    }
                } finally {
                    fclose($input);
                    fclose($cipher);
                    fclose($output);
                }
            }
        } finally {
            stream_wrapper_unregister('ciphersweetshort');
        }
    }

    public function testInvalidSizesPreserveDestination(): void
    {
        $key = new SymmetricKey(str_repeat('K', 32));
        foreach ([new BoringCrypto(), new FIPSCrypto(), new ModernCrypto()] as $backend) {
            foreach ([0, -1] as $size) {
                foreach (['doStreamEncrypt', 'doStreamDecrypt'] as $method) {
                    $input = self::stream();
                    $output = self::stream('unchanged');
                    try {
                        try {
                            $backend->$method($input, $output, $key, $size);
                            self::fail('Invalid chunk size accepted');
                        } catch (CryptoOperationException $ex) {
                            $this->assertSame('Chunk size must be positive', $ex->getMessage());
                        }
                        rewind($output);
                        $this->assertSame('unchanged', stream_get_contents($output));
                    } finally {
                        fclose($input);
                        fclose($output);
                    }
                }
            }
        }
    }

    public function testVersionMarkerIsAuthenticated(): void
    {
        $key = new SymmetricKey(str_repeat('K', 32));
        foreach ([new BoringCrypto(), new FIPSCrypto(), new ModernCrypto()] as $backend) {
            $input = self::stream(str_repeat('A', 200));
            $cipher = self::stream();
            $output = self::stream('unchanged');
            try {
                $backend->doStreamEncrypt($input, $cipher, $key, 65);
                fwrite($cipher, $backend->getPrefix());
                try {
                    $backend->doStreamDecrypt($cipher, $output, $key, 65);
                    self::fail('Unauthenticated version change accepted');
                } catch (CryptoOperationException $ex) {
                    $this->assertSame('Invalid authentication tag', $ex->getMessage());
                }
                rewind($output);
                $this->assertSame('unchanged', stream_get_contents($output));
            } finally {
                fclose($input);
                fclose($cipher);
                fclose($output);
            }
        }
    }
}
