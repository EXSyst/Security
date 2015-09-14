<?php

namespace EXSyst\Component\Security\TOTP\Tests;

use EXSyst\Component\Security\TOTP\TOTPKeyGenerator;

class KeyGenerationTest extends \PHPUnit_Framework_TestCase
{
    private $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public function testKeyGeneration()
    {
        for ($i = 0; $i < 15; $i++) {
            $length = rand(8, 100);
            $key = TOTPKeyGenerator::generate($length);
            $this->assertRegExp(sprintf('#[ABCDEFGHIJKLMNOPQRSTUVWXYZ234567]{%d}#', $length), $key);
        }
    }
}
