<?php
namespace EXSyst\Component\Security\TOTP;

use EXSyst\Component\Security\Exception\InvalidArgumentException;

class TOTPTimeManager
{
    const DEFAULT_STAMP_LENGTH = 30;

    /**
     * @var integer
     */
    private $stampLength;

    /**
     * @param integer|null $stampLength Length of a unit time (default 30)
     */
    public function __construct($stampLength = null) {
        $this->setStampLength($stampLength);
    }

    /**
     * @param integer|null $stampLength Length of a unit time (default 30)
     * @return TOTPTimeManager
     */
    public function setStampLength($stampLength = null) {
        if($stampLength === null)
            $stampLength = self::DEFAULT_STAMP_LENGTH;
        $stampLength = intval($stampLength);
        if(empty($stampLength) or $stampLength < 0)
            throw new InvalidArgumentException('Stamp length must be greater than 0 and positive.');
        $this->stampLength = $stampLength;

        return $this;
    }

    /**
     * @return integer Stamp length
     */
    public function getStampLength() {
        return $this->stampLength;
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
     * @param integer $time timestamp
     * @return integer stamp corresponding to the timestamp provided
     */
    public function getStamp($time) {
        return floor($time / $this->stampLength);
    }
}
