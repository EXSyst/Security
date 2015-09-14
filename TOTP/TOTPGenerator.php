<?php

namespace EXSyst\Component\Security\TOTP;

use EXSyst\Component\Security\Exception\TooShortKeyException;

/**
 * TOTP code generator.
 */
class TOTPGenerator
{
    /**
     * Base 32 table.
     *
     * @var array
     */
    private static $lut = [
        'A' => 0,    'B' => 1,
        'C' => 2,    'D' => 3,
        'E' => 4,    'F' => 5,
        'G' => 6,    'H' => 7,
        'I' => 8,    'J' => 9,
        'K' => 10,    'L' => 11,
        'M' => 12,    'N' => 13,
        'O' => 14,    'P' => 15,
        'Q' => 16,    'R' => 17,
        'S' => 18,    'T' => 19,
        'U' => 20,    'V' => 21,
        'W' => 22,    'X' => 23,
        'Y' => 24,    'Z' => 25,
        '2' => 26,    '3' => 27,
        '4' => 28,    '5' => 29,
        '6' => 30,    '7' => 31,
    ];

    /**
     * Generates a TOTP code.
     *
     * @param int    $stamp Unit time
     * @param string $key   TOTP key
     *
     * @return string TOTP corresponding to the key and stamp provided
     */
    public static function generate($stamp, $key)
    {
        $key = self::base32_decode($key);
        if (strlen($key) < 8) {
            throw new TooShortKeyException('Secret key is too short. Must be at least 16 base 32 characters');
        }

        $bin_counter = pack('N*', 0).pack('N*', $stamp);        // Stamp must be 64-bit int
        $hash = hash_hmac('sha1', $bin_counter, $key, true);

        return str_pad(self::oath_truncate($hash), 6, '0', STR_PAD_LEFT);
    }

    /**
     * Decodes a base 32 string.
     *
     * @param mixed Base 32 string to decode
     *
     * @return string Base 32 string decoded
     */
    protected static function base32_decode($b32)
    {
        $b32 = strtoupper($b32);

        if (!preg_match('/^[ABCDEFGHIJKLMNOPQRSTUVWXYZ234567]+$/', $b32, $match)) {
            throw new Exception('Invalid characters in the base32 string.');
        }

        $l = strlen($b32);
        $n = 0;
        $j = 0;
        $binary = '';

        for ($i = 0; $i < $l; $i++) {
            $n = $n << 5;                    // Move buffer left by 5 to make room
            $n = $n + self::$lut[$b32[$i]]; // Add value into buffer
            $j = $j + 5;                    // Keep track of number of bits in buffer

            if ($j >= 8) {
                $j = $j - 8;
                $binary .= chr(($n & (0xFF << $j)) >> $j);
            }
        }

        return $binary;
    }

    protected static function oath_truncate($hash)
    {
        $offset = ord($hash[19]) & 0xf;

        return (
            ((ord($hash[$offset + 0]) & 0x7f) << 24) |
            ((ord($hash[$offset + 1]) & 0xff) << 16) |
            ((ord($hash[$offset + 2]) & 0xff) << 8) |
            (ord($hash[$offset + 3]) & 0xff)
        ) % 1000000;
    }
}
