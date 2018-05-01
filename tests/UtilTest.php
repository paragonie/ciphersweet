<?php
namespace ParagonIE\CipherSweet\Tests;

use ParagonIE\CipherSweet\Util;
use ParagonIE\ConstantTime\Hex;
use PHPUnit\Framework\TestCase;

/**
 * Class UtilTest
 * @package ParagonIE\CipherSweet\Tests
 */
class UtilTest extends TestCase
{
    public function testAes256Ctr()
    {
        $key = \random_bytes(32);
        $nonce = \random_bytes(16);
        for ($i = 0; $i < 10; ++$i) {
            $message = \random_bytes(16 << $i);
            $expected = \openssl_encrypt(
                $message,
                'aes-256-ctr',
                $key,
                OPENSSL_RAW_DATA,
                $nonce
            );
            $actual = Util::aes256ctr($message, $key, $nonce);
            $this->assertSame(
                Hex::encode($expected),
                Hex::encode($actual)
            );
        }
    }

    /**
     * @throws \SodiumException
     */
    public function testBitMask()
    {
        $testCases = [
            ['ff', 4, 'f0', '0f'],
            ['ff', 9, 'ff00', 'ff00'],
            ['ffffffff', 16, 'ffff', 'ffff'],
            ['ffffffff', 17, 'ffff80', 'ffff01'],
            ['ffffffff', 18, 'ffffc0', 'ffff03'],
            ['ffffffff', 19, 'ffffe0', 'ffff07'],
            ['ffffffff', 20, 'fffff0', 'ffff0f'],
            ['ffffffff', 21, 'fffff8', 'ffff1f' ],
            ['ffffffff', 22, 'fffffc', 'ffff3f'],
            ['ffffffff', 23, 'fffffe', 'ffff7f'],
            ['ffffffff', 24, 'ffffff', 'ffffff'],
            ['ffffffff', 32, 'ffffffff', 'ffffffff'],
            ['ffffffff', 64, 'ffffffff00000000', 'ffffffff00000000'],
            ['55f6778c', 11, '55e0', '5506'],
            ['55f6778c', 12, '55f0', '5506'],
            ['55f6778c', 13, '55f0', '5516'],
            ['55f6778c', 14, '55f4', '5536'],
            ['55f6778c', 15, '55f6', '5576'],
            ['55f6778c', 16, '55f6', '55f6'],
            ['55f6778c', 17, '55f600', '55f601'],
            ['55f6778c', 32, '55f6778c', '55f6778c']
        ];
        foreach ($testCases as $testCase) {
            list ($input, $size, $output, $outputRight) = $testCase;
            $this->assertSame(
                $output,
                Hex::encode(
                    Util::andMask(Hex::decode($input), $size)
                )
            );
            $this->assertSame(
                $outputRight,
                Hex::encode(
                    Util::andMask(Hex::decode($input), $size, true)
                )
            );
        }
    }

    public function testCtrNonceIncrease()
    {
        $testCases = [
            [
                '00000000000000000000000000000001',
                '00000000000000000000000000000000'
            ],
            [
                '00000000000000000000000000000100',
                '000000000000000000000000000000ff'
            ],
            [
                '0000000000000000000000000000ff00',
                '0000000000000000000000000000feff'
            ],
            [
                '00000000000000000000000000000000',
                'ffffffffffffffffffffffffffffffff'
            ]
        ];
        foreach ($testCases as $testCase) {
            list ($output, $input) = $testCase;
            $this->assertSame(
                $output,
                Hex::encode(Util::ctrNonceIncrease(Hex::decode($input)))
            );
        }
    }
}
