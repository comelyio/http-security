<?php
/**
 * This file is part of Comely package.
 * https://github.com/comelyio/comely
 *
 * Copyright (c) 2016-2018 Furqan A. Siddiqui <hello@furqansiddiqui.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code or visit following link:
 * https://github.com/comelyio/comely/blob/master/LICENSE
 */

declare(strict_types=1);

namespace Comely\IO\HttpSecurity;

use Comely\IO\HttpSecurity\Exception\ObfuscatedFormsException;
use Comely\IO\HttpSecurity\ObfuscatedForms\Form;
use Comely\IO\Session\ComelySession;

/**
 * Class ObfuscatedForms
 * @package Comely\IO\HttpSecurity
 */
class ObfuscatedForms
{
    /** @var ComelySession */
    private $session;

    /**
     * ObfuscatedForms constructor.
     * @param ComelySession $session
     */
    public function __construct(ComelySession $session)
    {
        $this->session = $session;
    }

    /**
     * @param string $name
     * @param string[] ...$fields
     * @return Form
     * @throws ObfuscatedFormsException
     * @throws \Comely\IO\Session\Exception\ComelySessionException
     */
    public function get(string $name, string ...$fields): Form
    {
        return $this->retrieve($name, false) ?? $this->obfuscate($name, ...$fields);
    }

    /**
     * @param string $name
     * @param string[] ...$fields
     * @return Form
     * @throws ObfuscatedFormsException
     * @throws \Comely\IO\Session\Exception\ComelySessionException
     */
    public function obfuscate(string $name, string ...$fields): Form
    {
        // Generate
        try {
            $form = new Form($name, ...$fields);
        } catch (ObfuscatedFormsException $e) {
            if ($e->getCode() === Form::SIGNAL_RETRY) {
                trigger_error($e->getMessage(), E_USER_NOTICE);
                return $this->obfuscate($name, ...$fields);
            }

            throw $e; // Throw exception
        }

        // Store
        $this->session->meta()->bag("obfuscated_forms")
            ->set($form->name(), serialize($form));

        return $form;
    }

    /**
     * @param string $name
     * @param bool $purge
     * @return Form|null
     * @throws ObfuscatedFormsException
     */
    public function retrieve(string $name, bool $purge = false): ?Form
    {
        if (!preg_match('/^[\w\-\.]{3,32}$/', $name)) {
            throw new ObfuscatedFormsException('Invalid form name');
        }

        $form = $this->session->meta()->bag("obfuscated_forms")
            ->get($name);

        if (!$form) {
            return null;
        }

        $form = unserialize(strval($form), [
            "allowed_classes" => ['Comely\IO\HttpSecurity\ObfuscatedForms\Form']
        ]);

        if (!$form instanceof Form) {
            trigger_error(
                sprintf('An error occurred while retrieving serialized obfuscated form "%s"', $name),
                E_USER_WARNING
            );

            $this->purge($name); // force purge corrupt/incomplete data
            return null;
        }

        if ($purge) {
            $this->purge($name);
        }

        return $form;
    }

    /**
     * @param string $name
     * @return ObfuscatedForms
     */
    public function purge(string $name): self
    {
        $this->session->meta()->bag("obfuscated_forms")->delete($name);
        return $this;
    }

    /**
     * @return ObfuscatedForms
     */
    public function flush(): self
    {
        $this->session->meta()->delete("obfuscated_forms");
        return $this;
    }
}