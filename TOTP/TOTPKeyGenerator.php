<?php
namespace EXSyst\Component\Security\TOTP;

/**
 * TOTP key generator
 */
class TOTPKeyGenerator
{
    const DEFAULT_LENGTH = 16;

    /**
     * Generates a TOTP key
     *
     * @param integer|null $length Key length (default 16)
     * @return string TOTP key
     */
    public static function generate($length = null){
        if($length === null)
            $length = self::DEFAULT_LENGTH;
        $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $randomString = '';
        for ($i = 0; $i < $length; $i++) {
            $randomString .= $characters[rand(0, strlen($characters) - 1)];
        }
        return $randomString;
    }
}
