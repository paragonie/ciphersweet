<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\KeyProvider;

use ParagonIE\CipherSweet\Util;
use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use ParagonIE\CipherSweet\Contract\KeyProviderInterface;
use ParagonIE\CipherSweet\Exception\KeyProviderException;
use ParagonIE\CipherSweet\Exception\CryptoOperationException;
/**
 * Class FileProvider
 * @package ParagonIE\CipherSweet\KeyProvider
 */
class FileProvider implements KeyProviderInterface
{
    /**
     * @var string|null $symmetricKeyPath
     */
    protected ?string $symmetricKeyPath = null;

    /**
     * FileProvider constructor.
     *
     * @param string|null $symmetricKeyPath
     */
    public function __construct(
        ?string $symmetricKeyPath = null
    ) {
        $this->symmetricKeyPath = $symmetricKeyPath;
    }

    /**
     * @return SymmetricKey
     * @throws KeyProviderException
     */
    public function getSymmetricKey(): SymmetricKey
    {
        if (\is_null($this->symmetricKeyPath)) {
            throw new KeyProviderException('Symmetric key path was not provided');
        }
        $contents = \file_get_contents($this->symmetricKeyPath);
        if (!\is_string($contents)) {
            throw new KeyProviderException('Could not read symmetric key from file.');
        }

        try{
            // If hash has string hashes or base64 key decode it
            $binaryKey = Util::convertSymmetricStringKeyToBinary(trim($contents));
            return new SymmetricKey($binaryKey);
        }catch(CryptoOperationException $e){
           
        }
        
        // otherwise read as binary
        return new SymmetricKey($contents);
    }

    /**
     * @return array
     */
    public function __debugInfo()
    {
        return ['symmetricKeyPath'];
    }
}
