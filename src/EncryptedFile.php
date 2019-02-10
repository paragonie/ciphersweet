<?php
namespace ParagonIE\CipherSweet;

use ParagonIE\CipherSweet\Backend\FIPSCrypto;
use ParagonIE\CipherSweet\Backend\ModernCrypto;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;
use ParagonIE\CipherSweet\Exception\FilesystemException;

/**
 * Class EncryptedFile
 * @package ParagonIE\CipherSweet
 */
class EncryptedFile
{
    /** @var int $chunkSize */
    protected $chunkSize;

    /** @var CipherSweet $engine */
    protected $engine;

    /**
     * EncryptedFile constructor.
     * @param CipherSweet $engine
     * @param int $chunkSize
     */
    public function __construct(CipherSweet $engine, $chunkSize = 8192)
    {
        $this->engine = $engine;
        $this->chunkSize = $chunkSize;
    }

    /**
     * @return CipherSweet
     */
    public function getEngine()
    {
        return $this->engine;
    }

    /**
     * @param string $inputFile
     * @param string $outputFile
     * @return bool
     *
     * @throws CryptoOperationException
     * @throws FilesystemException
     */
    public function decryptFile($inputFile, $outputFile)
    {
        if (\realpath($inputFile) === \realpath($outputFile)) {
            $inputRealStream = $this->getStreamForFile($inputFile, 'rb');
            $inputStream = $this->copyStreamToTemp($inputRealStream);
            \fclose($inputRealStream);
        } else {
            $inputStream = $this->getStreamForFile($inputFile, 'rb');
        }
        $outputStream = $this->getStreamForFile($outputFile);
        try {
            return $this->decryptStream($inputStream, $outputStream);
        } finally {
            \fclose($inputStream);
            \fclose($outputStream);
        }
    }

    /**
     * @param string $inputFile
     * @param string $outputFile
     * @param string $password
     * @return bool
     *
     * @throws CryptoOperationException
     * @throws FilesystemException
     */
    public function decryptFileWithPassword($inputFile, $outputFile, $password)
    {
        if (\realpath($inputFile) === \realpath($outputFile)) {
            $inputRealStream = $this->getStreamForFile($inputFile, 'rb');
            $inputStream = $this->copyStreamToTemp($inputRealStream);
            \fclose($inputRealStream);
        } else {
            $inputStream = $this->getStreamForFile($inputFile, 'rb');
        }
        $outputStream = $this->getStreamForFile($outputFile);
        try {
            return $this->decryptStreamWithPassword(
                $inputStream,
                $outputStream,
                $password
            );
        } finally {
            \fclose($inputStream);
            \fclose($outputStream);
        }
    }

    /**
     * @param resource $inputFP
     * @param resource $outputFP
     * @return bool
     * @throws CryptoOperationException
     */
    public function decryptStream($inputFP, $outputFP)
    {
        $key = $this->engine->getFieldSymmetricKey(
            Constants::FILE_TABLE,
            Constants::FILE_COLUMN
        );
        return $this->engine->getBackend()->doStreamDecrypt(
            $inputFP,
            $outputFP,
            $key,
            $this->chunkSize
        );
    }

    /**
     * @param resource $inputFP
     * @param resource $outputFP
     * @param string $password
     * @throws CryptoOperationException
     * @return bool
     */
    public function decryptStreamWithPassword($inputFP, $outputFP, $password)
    {
        $backend = $this->engine->getBackend();
        $salt = $this->getSaltFromStream($inputFP);
        $key = $backend->deriveKeyFromPassword($password, $salt);
        return $backend->doStreamDecrypt(
            $inputFP,
            $outputFP,
            $key,
            $this->chunkSize
        );
    }

    /**
     * @param string $inputFile
     * @param string $outputFile
     * @return bool
     *
     * @throws CryptoOperationException
     * @throws FilesystemException
     */
    public function encryptFile($inputFile, $outputFile)
    {
        if (\realpath($inputFile) === \realpath($outputFile)) {
            $inputRealStream = $this->getStreamForFile($inputFile, 'rb');
            $inputStream = $this->copyStreamToTemp($inputRealStream);
            \fclose($inputRealStream);
        } else {
            $inputStream = $this->getStreamForFile($inputFile, 'rb');
        }
        $outputStream = $this->getStreamForFile($outputFile);
        try {
            return $this->encryptStream($inputStream, $outputStream);
        } finally {
            \fclose($inputStream);
            \fclose($outputStream);
        }
    }

    /**
     * @param string $inputFile
     * @param string $outputFile
     * @param string $password
     *
     * @throws CryptoOperationException
     * @throws FilesystemException
     * @return bool
     */
    public function encryptFileWithPassword($inputFile, $outputFile, $password)
    {
        if (\realpath($inputFile) === \realpath($outputFile)) {
            $inputRealStream = $this->getStreamForFile($inputFile, 'rb');
            $inputStream = $this->copyStreamToTemp($inputRealStream);
            \fclose($inputRealStream);
        } else {
            $inputStream = $this->getStreamForFile($inputFile, 'rb');
        }
        $outputStream = $this->getStreamForFile($outputFile);
        try {
            return $this->encryptStreamWithPassword(
                $inputStream,
                $outputStream,
                $password
            );
        } finally {
            \fclose($inputStream);
            \fclose($outputStream);
        }
    }

    /**
     * @param resource $inputFP
     * @param resource $outputFP
     * @return bool
     *
     * @throws CryptoOperationException
     */
    public function encryptStream($inputFP, $outputFP)
    {
        $key = $this->engine->getFieldSymmetricKey(
            Constants::FILE_TABLE,
            Constants::FILE_COLUMN
        );
        return $this->engine->getBackend()->doStreamEncrypt(
            $inputFP,
            $outputFP,
            $key,
            $this->chunkSize
        );
    }

    /**
     * @param resource $inputFP
     * @param resource $outputFP
     * @param string $password
     * @throws CryptoOperationException
     * @return bool
     */
    public function encryptStreamWithPassword($inputFP, $outputFP, $password)
    {
        try {
            // Do not generate a dummy salt!
            do {
                $salt = \random_bytes(16);
            } while (Util::hashEquals(Constants::DUMMY_SALT, $salt));
        } catch (\Exception $ex) {
            throw new CryptoOperationException('RNG failure');
        }

        $backend = $this->engine->getBackend();
        $key = $backend->deriveKeyFromPassword($password, $salt);
        return $backend->doStreamEncrypt(
            $inputFP,
            $outputFP,
            $key,
            $this->chunkSize,
            $salt
        );
    }

    /**
     * @param resource $inputFP
     * @return string
     * @throws CryptoOperationException
     */
    public function getSaltFromStream($inputFP)
    {
        $backend = $this->engine->getBackend();
        if ($backend instanceof FIPSCrypto) {
            \fseek($inputFP, 53, SEEK_SET);
        } else if ($backend instanceof ModernCrypto) {
            \fseek($inputFP, 21, SEEK_SET);
        } else {
            throw new CryptoOperationException('Unknown cipher backend');
        }
        /** @var string $salt */
        $salt = \fread($inputFP, 16);
        \fseek($inputFP, 0, SEEK_SET);
        return $salt;
    }

    /**
     * @param string $fileName
     * @param string $mode
     * @return resource
     * @throws FilesystemException
     */
    public function getStreamForFile($fileName = 'php://temp', $mode = 'wb')
    {
        $fp = \fopen($fileName, $mode);
        if (!\is_resource($fp)) {
            throw new FilesystemException('Could not create stream');
        }
        return $fp;
    }

    /**
     * @param resource $realStream
     * @return resource
     *
     * @throws FilesystemException
     */
    protected function copyStreamToTemp($realStream)
    {
        $inputStream = $this->getStreamForFile();
        \fseek($inputStream, 0, SEEK_SET);
        \fseek($realStream, 0, SEEK_SET);
        \stream_copy_to_stream($realStream, $inputStream);
        return $inputStream;
    }
}
