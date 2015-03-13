<?php
namespace EXSyst\Component\Security\TOTP;

use EXSyst\Component\Security\Exception\TooShortKeyException;

/**
 * TOTP code validator
 */
class TOTPValidator
{
	const DEFAULT_STAMP_WINDOW = 1;

    /**
     * @var TOTPTimeManager
     */
    protected $timeManager;

    /**
     * @param TOTPTimeManager|integer|null $stampLength Stamp length in seconds
     * @param integer|null $window accepted stamps before and after the current stamp
     */
    public function __construct($window = null, $stampLength = null) {
		// Window definition
		if($window === null)
			$this->window = self::DEFAULT_STAMP_WINDOW;
		else
			$this->window = intval($window);

		// stamp length definition
        if(!($stampLength instanceof TOTPTimeManager))
            $this->timeManager = new TOTPTimeManager(intval($stampLength));
        else
            $this->timeManager = $stampLength;
    }

	/**
	 * Check if a totp corresponds to a key and a stamp
	 *
	 * @param string $key
	 * @param integer $totp
	 *
	 * @return bool Return true if the totp corresponds to the key and the stamp provided
	 */
    public function validate($totp, $key, $stamp = null){
        if($stamp === null)
            $stamp = $this->timeManager->getCurrentStamp();

        if (!preg_match('/^[0-9]{6}$/', $totp))
            return false;
        $totp = intval($totp);

        // Search the stamp corresponding to the totp provided
		for ($st = $stamp - $this->window; $st <= $stamp + $this->window; $st++)
			if (($res = TOTPGenerator::generate($st, $key)) == $totp)
				return $st;

        return false;
    }

    /**
     * @return TOTPTimeManager
     */
    public function getTimeManager() {
        return $this->timeManager;
    }
}
