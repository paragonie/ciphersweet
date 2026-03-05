<?php
declare(strict_types=1);
namespace KnownAnswers;

use ParagonIE\CipherSweet\Backend\BoringCrypto;
use ParagonIE\CipherSweet\Backend\FIPSCrypto;
use ParagonIE\CipherSweet\Backend\ModernCrypto;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\EncryptedRow;
use ParagonIE\CipherSweet\KeyProvider\StringProvider;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class EncryptDecrypt extends TestCase
{

    public static function jsonProviders(): array
    {

        $nistVectors = json_decode(file_get_contents(__DIR__ . '/nist.json'), true);
        $naclVectors = json_decode(file_get_contents(__DIR__ . '/nacl.json'), true);
        $boringVectors = json_decode(file_get_contents(__DIR__ . '/boring.json'), true);

        return [
            [
                new CipherSweet(
                    new StringProvider(sodium_hex2bin($nistVectors['key'])),
                    new FIPSCrypto()
                ),
                $nistVectors['name'],
                $nistVectors['testCases']
            ],
            [
                new CipherSweet(
                    new StringProvider(sodium_hex2bin($naclVectors['key'])),
                    new ModernCrypto()
                ),
                $naclVectors['name'],
                $naclVectors['testCases']
            ],
            [
                new CipherSweet(
                    new StringProvider(sodium_hex2bin($boringVectors['key'])),
                    new BoringCrypto()
                ),
                $boringVectors['name'],
                $boringVectors['testCases']
            ],
        ];
    }

    #[DataProvider("jsonProviders")]
    public function testVectors(CipherSweet $engine, string $name, array $testCases): void
    {
        $this->simpleTest($engine, $name, $testCases['simple']);
    }

    protected function simpleTest(CipherSweet $engine, string $name, array $testCase): void
    {
        $eR = (new EncryptedRow($engine, 'example'))
            ->addTextField('name')
            ->addIntegerField('age')
            ->addFloatField('grade')
            ->addBooleanField('pass');
        foreach ($testCase['ciphertext'] as $index => $row) {
            $plaintext = $eR->decryptRow($row);
            foreach ($plaintext as $k => $v) {
                $this->assertSame($testCase['plaintext'][$index][$k], $v, $name . ' simple | key = ' . $k);
            }
        }
    }
}
