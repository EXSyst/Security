<?php
namespace EXSyst\Component\Security\TOTP;

use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;

use Doctrine\Common\Persistence\ObjectManager;

use XN\Security\TOTPAuthenticatableInterface;

class TOTPAuthenticationListener
{
	private $em;
	private $maxTrials;

	public function __construct(ObjectManager $em, TOTP $maxTrials = null, $amplitude = null)
	{
		$this->em = $em;
		$this->maxTrials = $maxTrials;
	}

	public function onSecurityInteractiveLogin(InteractiveLoginEvent $event)
	{
		$user = $event->getAuthenticationToken()->getUser();
		if (!$user)
			return;
		if (!($user instanceof TOTPAuthenticatableInterface))
			return;
		$key = $user->getTOTPSecretKey();
		if (!$key)
			return;
		$stamp = self::getCurrentStamp();
		if ($user->getTOTPLastTrialStamp() === null || $user->getTOTPLastTrialStamp() < $stamp) {
			$user->setTOTPLastTrialStamp($stamp);
			$user->setTOTPTrialCount(0);
		}
		if ($user->getTOTPTrialCount() >= $this->maxTrials)
			throw new AuthenticationException("Bad credentials");
		$request = $event->getRequest();
		$totp = trim($request->request->get('_totp'));
		if (!preg_match('/^[0-9]{6}$/', $totp))
			throw new AuthenticationException("Bad credentials");
		$totp = intval($totp);
		if (self::hash($stamp + 1, $key) == $totp)
			$totpStamp = $stamp + 1;
		elseif (self::hash($stamp, $key) == $totp)
			$totpStamp = $stamp;
		elseif (self::hash($stamp - 1, $key) == $totp)
			$totpStamp = $stamp - 1;
		else
			$totpStamp = null;
		if ($totpStamp !== null && ($user->getTOTPLastSuccessStamp() === null || $totpStamp > $user->getTOTPLastSuccessStamp())) {
			$user->setTOTPLastTrialStamp(max($user->getTOTPLastTrialStamp(), $totpStamp));
			$user->setTOTPLastSuccessStamp(($user->getTOTPLastSuccessStamp() === null) ? $totpStamp : max($user->getTOTPLastSuccessStamp(), $totpStamp));
			$user->setTOTPTrialCount($this->maxTrials);
			$this->em->persist($user);
			$this->em->flush($user);
		} else {
			$user->setTOTPTrialCount($user->getTOTPTrialCount() + 1);
			$this->em->persist($user);
			$this->em->flush($user);
			throw new AuthenticationException("Bad credentials");
		}
	}
}
