<?php
namespace EXSyst\Component\Security\TOTP\Tests;

use EXSyst\Component\Security\TOTP\TOTPTimeManager;
use EXSyst\Component\Security\TOTP\TOTPKeyGenerator;
use EXSyst\Component\Security\TOTP\TOTPGenerator;
use EXSyst\Component\Security\TOTP\TOTPValidator;

class ValidatorTest extends \PHPUnit_Framework_TestCase
{
    protected $validator;
    protected $key;

    protected function setUp() {
        $tm = new TOTPTimeManager();
        $this->stamp = $tm->getCurrentStamp();
        $this->validator = new TOTPValidator(35, 5);
        $this->key = TOTPKeyGenerator::generate();
    }

    public function testValidator() {
        for($t = 0; $t < 10; $t++) {
            $stamp = $this->stamp + rand(-300, 300);
            for($i = -5; $i <= 5; $i++) {
                $totp = TOTPGenerator::generate($stamp + $i, $this->key);
                $this->assertEquals($stamp + $i, $this->validator->validate($totp, $this->key, $stamp + $i),
                    sprintf('Error during checking totp "%s" with the key "%s", the stamp "%d" and with %s stamp added', $totp, $this->key, $stamp, $i));
            }
            $totp = TOTPGenerator::generate($stamp + 6, $this->key);
            $this->assertFalse($this->validator->validate($totp, $this->key, $stamp),
                sprintf('Must be false : totp "%s" with key "%s" and stamp %d + 6', $totp, $this->key, $stamp));
        }
    }
}
