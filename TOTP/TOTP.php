<?php
namespace EXSyst\Component\Security\TOTP;

/**
 * TOTP - for Time-based One-time Password Algorithm - is a security for authentication.
 * It uses a key given to the user that allow him to generates a totp code
 * that is provided to the server.
 * It's based on a stamp unit time which represents standarly 30 seconds but could be changed.
 */
class TOTP
{
	/**
	* @var TOTPValidator
	*/
	protected $validator;

	/**
	 * @param integer|null $stampLength stamp length in seconds
	 * @param integer|null $window accepted stamps before and after the current stamp
	 */
	public function __construct($stampLength = null, $window = null) {
		$this->validator = new TOTPValidator($stampLength, $window);
	}

	/**
	 * Alias of {@link TOTPGenerator::generate()}
	 */
	public static function generateKey($length = null){
		return TOTPKeyGenerator::generate($length);
	}

	/**
	 * Alias of {@link TOTPGenerator::generate()}
	 */
	public static function generateTOTP($stamp, $key){
		return TOTPGenerator::generate($stamp, $key);
	}

	/**
	 * Alias of {@link TOTPValidator::validate()}
	 */
	public function validate($key, $totp, $stamp = null)
	{
		return $this->validator($key, $totp, $stamp);
	}

	/**
	 * Alias of {@link TOTPValidator::getTimeManager()}
	 */
	public function getTimeManager() {
		return $this->validator->getTimeManager();
	}
}
