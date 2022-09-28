<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\Tests\Interop;

use ParagonIE\CipherSweet\Backend\BoringCrypto;
use ParagonIE\CipherSweet\Backend\Key\SymmetricKey;
use PHPUnit\Framework\TestCase;

class JavaScriptTest extends TestCase
{
    public function testJavascriptCompat()
    {
        $exampleKey = new SymmetricKey(sodium_hex2bin('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'));
        $ciphertext = 'brng:m3y71cMwhTB2e8YjPLzZ2mwBoMRP1BgqVs_He47bRT5DJbWVBwG_cNsn6xvsl4rT2Cu1QSOEFt_lRECl3w524LlzGwgZ30UDm1KfgaTi9scjmu4=';
        $plaintext = (new BoringCrypto())->decrypt($ciphertext, $exampleKey);
        $this->assertSame('This is just a test message', $plaintext);

        $exampleKey = new SymmetricKey(sodium_hex2bin('0b036de5605144ea7aeed8bd3a191c08fe1b0ed69d9c8ba0dcbe82372451bb31'));
        $ciphertext = 'brng:s0oCG2qoJMTWNreJ3AYQhTYSL423gsDYFKmSMDBzOUubIbiNPWSFZmD8uXMO5dmAhuCf5dvTCtfVvl8MADVL0dmub-znB7nEDYH2eMJBCmX-Qyc=';
        $plaintext = (new BoringCrypto())->decrypt($ciphertext, $exampleKey);
        $this->assertSame('This is just a test message', $plaintext);
    }
}