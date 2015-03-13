<?php
namespace EXSyst\Component\Security\TOTP;

use EXSyst\Component\Security\Exception\TooShortKeyException;

/**
 * TOTP - for Time-based One-time Password Algorithm - is a security for authentication.
 * It uses a key given to the user that allow him to generates a totp code
 * that is provided to the server.
 * It's based on a stamp unit time which represents standarly 30 seconds but could be changed.
 */
class TOTP
{
	const DEFAULT_AMPLITUDE = 1;
	const DEFAULT_STAMP_LENGTH = 30;

	/**
	 * @var integer
	 */
	private $amplitude;

	private static $lut = [
		"A" => 0,	"B" => 1,
		"C" => 2,	"D" => 3,
		"E" => 4,	"F" => 5,
		"G" => 6,	"H" => 7,
		"I" => 8,	"J" => 9,
		"K" => 10,	"L" => 11,
		"M" => 12,	"N" => 13,
		"O" => 14,	"P" => 15,
		"Q" => 16,	"R" => 17,
		"S" => 18,	"T" => 19,
		"U" => 20,	"V" => 21,
		"W" => 22,	"X" => 23,
		"Y" => 24,	"Z" => 25,
		"2" => 26,	"3" => 27,
		"4" => 28,	"5" => 29,
		"6" => 30,	"7" => 31
	];

	/**
	 * @param integer|null $stampLength stamp length in seconds
	 * @param integer|null $amplitude accepted stamps before and after the current stamp
	 */
	public function __construct($stampLength = null, $amplitude = null) {
		if($stampLength === null)
			$amplitude = self::DEFAULT_STAMP_LENGTH;
		$this->stampLength = intval($stampLength);

		if($amplitude === null)
			$amplitude = self::DEFAULT_AMPLITUDE;
		$this->amplitude = intval($amplitude);
	}

	/**
	* Generates a totp key
	*
	* @param integer $length key length
	*/
	public static function generateKey($length = 16){
		$characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$randomString = '';
		for ($i = 0; $i < $length; $i++) {
			$randomString .= $characters[rand(0, strlen($characters) - 1)];
		}
		return $randomString;
	}

	/**
	 * Check if a totp corresponds to a key and a stamp
	 *
	 * @param string $key
	 * @param integer $totp
	 *
	 * @return bool Return true if the totp corresponds to the key and the stamp provided
	 */
	public function checkTotp($key, $totp, $stamp = null)
	{
		$stamp = intval($stamp);
		if($stamp === null)
			$stamp = $this->getCurrentStamp();
		if (!preg_match('/^[0-9]{6}$/', $totp))
			return false;
		$totp = intval($totp);

		// Search the stamp corresponding to the totp provided
		$totpStamp = null;
		if (self::hash($stamp, $key) == $totp)
			$totpStamp = $stamp;
		elseif(!empty($this->amplitude)) {
			for($i = 1; $i <= $this->amplitude; $i++)
				if (self::hash($stamp + $i, $key) == $totp){
					$totpStamp = $stamp + $i;
					break;
				}
				elseif (self::hash($stamp - $i, $key) == $totp){
					$totpStamp = $stamp - $i;
					break;
				}
		}

		if ($totpStamp !== null)
			return [ 'stamp' => $totpStamp ];
		else
			return false;
	}

	/**
	 * @return integer Current stamp
	 */
	public function getCurrentStamp()
	{
		return $this->getStamp(time());
	}

	/**
	 * Returns the stamp corresponding to the specified time
	 *
	 * @param integer $time
	 *
	 * @return integer stamp
	 */
	public function getStamp($time) {
		return floor($time / $this->stampLength);
	}

	/**
	 * Generates a TOTP code
	 *
	 * @param integer $stamp
	 * @param string $key
	 *
	 * @return string TOTP corresponding to the key and stamp provided
	 */
	public static function hash($stamp, $key)
	{
		$key = self::base32_decode($key);
		if (strlen($key) < 8)
			throw new TooShortKeyException('Secret key is too short. Must be at least 16 base 32 characters');

		$bin_counter = pack('N*', 0) . pack('N*', $stamp);
		$hash = hash_hmac ('sha1', $bin_counter, $key, true);

		return self::oath_truncate($hash);
	}

	/**
	 * Decodes a base 32 string
	 *
	 * @param mixed Base 32 string to decode
	 * @return string Base 32 string decoded
	 */
	public static function base32_decode($b32)
	{
		$b32 = strtoupper($b32);

		if (!preg_match('/^[ABCDEFGHIJKLMNOPQRSTUVWXYZ234567]+$/', $b32, $match))
			throw new Exception('Invalid characters in the base32 string.');

		$l = strlen($b32);
		$n = 0;
		$j = 0;
		$binary = "";

		for ($i = 0; $i < $l; $i++) {
			$n = $n << 5; 					// Move buffer left by 5 to make room
			$n = $n + self::$lut[$b32[$i]]; // Add value into buffer
			$j = $j + 5;					// Keep track of number of bits in buffer

			if ($j >= 8) {
				$j = $j - 8;
				$binary .= chr(($n & (0xFF << $j)) >> $j);
			}
		}

		return $binary;
	}

	private static function oath_truncate($hash)
	{
	    $offset = ord($hash[19]) & 0xf;

	    return (
	        ((ord($hash[$offset+0]) & 0x7f) << 24 ) |
	        ((ord($hash[$offset+1]) & 0xff) << 16 ) |
	        ((ord($hash[$offset+2]) & 0xff) << 8 ) |
	        (ord($hash[$offset+3]) & 0xff)
	    ) % 1000000;
	}
}
