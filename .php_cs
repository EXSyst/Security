<?php

use Symfony\CS\Config\Config;
use Symfony\CS\Finder\DefaultFinder;
use Symfony\CS\Fixer\Contrib\HeaderCommentFixer;
use Symfony\CS\FixerInterface;

$finder = DefaultFinder::create()
    ->in(__DIR__)
;

$header = <<<EOF
This file is part of the Security package.

(c) EXSyst

For the full copyright and license information, please view the LICENSE
file that was distributed with this source code.
EOF;
HeaderCommentFixer::setHeader($header);

return Config::create()
    ->level(FixerInterface::SYMFONY_LEVEL)
    ->fixers([
        'align_double_arrow',
        'header_comment',
        'ordered_use',
        'short_array_syntax',
    ])
    ->finder($finder)
    ->setUsingCache(true)
;
