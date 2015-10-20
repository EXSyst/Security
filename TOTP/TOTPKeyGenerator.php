<?php

/*
 * This file is part of the Security package.
 *
 * (c) EXSyst
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace EXSyst\Component\Security\TOTP;

/**
 * TOTP key generator.
 */
class TOTPKeyGenerator
{
    const DEFAULT_LENGTH = 16;

    /**
     * Generates a TOTP key.
     *
     * @param int|null $length Key length (default 16)
     *
     * @return string TOTP key
     */
    public static function generate($length = null)
    {
        if ($length === null) {
            $length = self::DEFAULT_LENGTH;
        }
        $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $randomString = '';
        for ($i = 0; $i < $length; ++$i) {
            $randomString .= $characters[rand(0, strlen($characters) - 1)];
        }

        return $randomString;
    }
}
