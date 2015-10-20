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

use EXSyst\Component\Security\Exception\InvalidArgumentException;

class TOTPTimeManager
{
    const DEFAULT_STAMP_LENGTH = 30;

    /**
     * @var int
     */
    private $stampLength;

    /**
     * @param int|null $stampLength Length of a unit time (default 30)
     */
    public function __construct($stampLength = null)
    {
        $this->setStampLength($stampLength);
    }

    /**
     * @param int|null $stampLength Length of a unit time (default 30)
     *
     * @return TOTPTimeManager
     */
    public function setStampLength($stampLength = null)
    {
        if ($stampLength === null) {
            $stampLength = self::DEFAULT_STAMP_LENGTH;
        }
        $stampLength = intval($stampLength);
        if (empty($stampLength) || $stampLength < 0) {
            throw new InvalidArgumentException('Stamp length must be greater than 0 and positive.');
        }
        $this->stampLength = $stampLength;

        return $this;
    }

    /**
     * @return int Stamp length
     */
    public function getStampLength()
    {
        return $this->stampLength;
    }

    /**
     * @return int Current stamp
     */
    public function getCurrentStamp()
    {
        return $this->getStamp(time());
    }

    /**
     * Returns the stamp corresponding to the specified time.
     *
     * @param int $time timestamp
     *
     * @return int stamp corresponding to the timestamp provided
     */
    public function getStamp($time)
    {
        return floor($time / $this->stampLength);
    }
}
