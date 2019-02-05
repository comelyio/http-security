<?php
/**
 * This file is part of Comely package.
 * https://github.com/comelyio/comely
 *
 * Copyright (c) 2016-2019 Furqan A. Siddiqui <hello@furqansiddiqui.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code or visit following link:
 * https://github.com/comelyio/comely/blob/master/LICENSE
 */

declare(strict_types=1);

namespace Comely\IO\HttpSecurity;

use Comely\IO\Session\ComelySession;
use Comely\Kernel\Extend\ComponentInterface;

/**
 * Class HttpSecurity
 * @package Comely\IO\HttpSecurity
 */
class HttpSecurity implements ComponentInterface
{
    /**
     * @param ComelySession $session
     * @return CSRF
     */
    public static function CSRF(ComelySession $session): CSRF
    {
        return new CSRF($session);
    }

    /**
     * @param ComelySession $session
     * @return ObfuscatedForms
     */
    public static function Obfuscator(ComelySession $session): ObfuscatedForms
    {
        return new ObfuscatedForms($session);
    }
}