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

use EXSyst\Component\Security\TOTP\TOTPTimeManager;

class TimeManagerTest extends \PHPUnit_Framework_TestCase
{
    protected $tm;

    protected function setUp()
    {
        $this->tm = [];
        for ($i = 0; $i < 10; ++$i) {
            $l = rand(1, 120);
            $this->tm[$l] = new TOTPTimeManager($l);
        }
    }

    public function testTimeManagerLenth()
    {
        foreach ($this->tm as $k => $v) {
            $this->assertEquals($k, $v->getStampLength());
        }
    }

    public function testValidator()
    {
        foreach ($this->tm as $k => $v) {
            $this->assertEquals(floor(time() / $k), $v->getCurrentStamp());

            $t2 = time() + rand(200, 10000);
            $this->assertEquals(floor($t2 / $k), $v->getStamp($t2));
        }
    }
}
