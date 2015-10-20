<?php

/*
 * This file is part of the Security package.
 *
 * (c) EXSyst
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace EXSyst\Component\Security\Tests\TOTP;

use EXSyst\Component\Security\TOTP\TOTPKeyGenerator;

class KeyGenerationTest extends \PHPUnit_Framework_TestCase
{
    private $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public function testKeyGeneration()
    {
        for ($i = 0; $i < 15; ++$i) {
            $length = rand(8, 100);
            $key = TOTPKeyGenerator::generate($length);
            $this->assertRegExp(sprintf('#[%s]{%d}#', $this->characters, $length), $key);
        }
    }
}
