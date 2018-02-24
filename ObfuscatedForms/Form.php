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

namespace Comely\IO\HttpSecurity\ObfuscatedForms;

use Comely\IO\HttpSecurity\Exception\ObfuscatedFormsException;

/**
 * Class Form
 * @package Comely\IO\HttpSecurity\ObfuscatedForms
 */
class Form implements \Serializable
{
    private const OBFUSCATED_KEY_BYTES = 6;
    public const SIGNAL_RETRY = 1100;

    /** @var string */
    private $name;
    /** @var array */
    private $obfuscated;
    /** @var array */
    private $fields;
    /** @var int */
    private $count;
    /** @var string */
    private $hash;
    /** @var null|array */
    private $input;

    /**
     * Form constructor.
     * @param string $name
     * @param string[] ...$fields
     * @throws ObfuscatedFormsException
     */
    public function __construct(string $name, string ...$fields)
    {
        if (!preg_match('/^\w{3,32}$/', $name)) {
            throw new ObfuscatedFormsException('Invalid form name');
        }

        $this->name = $name;
        $this->obfuscated = [];
        $this->fields = [];
        $this->count = 0;

        $count = count($fields);
        $keyLength = self::OBFUSCATED_KEY_BYTES * 2; // 2 hexits per byte
        $bytesNeeded = $count * self::OBFUSCATED_KEY_BYTES;

        try {
            $bytes = random_bytes(intval($bytesNeeded * 2));  // Just get twice as much
        } catch (\Exception $e) {
            throw new ObfuscatedFormsException('Failed to get random bytes from a cryptographically secure source');
        }

        $bytes = str_split($bytes, $keyLength);
        if (count($bytes) !== count(array_unique($bytes))) {
            // A repeating key detected, retry!
            throw new ObfuscatedFormsException(
                'Collision of obfuscated keys detected, attempt retry', self::SIGNAL_RETRY
            );
        }

        // Iterate through fields
        $pos = 0;
        $hash = "";
        foreach ($fields as $field) {
            if (!preg_match('/^\w{2,32}$/', $field)) {
                throw new ObfuscatedFormsException(sprintf('Form "%s" contains an invalid key', $name));
            }

            $key = $bytes[$pos];
            if (preg_match('/^[0-9]+$/', $key)) {
                $key{0} = "a"; // obfuscated keys should be alpha-numeric due to some javascript XHR libraries
            }

            $hash .= $key . "+" . $field;
            $this->obfuscated[$key] = $field;
            $this->fields[$field] = $key;
            $this->count++;
        }

        // Generate hash
        $this->hash = hash("sha1", $hash);
    }

    /**
     * @return string
     */
    public function serialize(): string
    {
        return base64_encode(serialize([
            "name" => $this->name,
            "hash" => $this->hash,
            "fields" => $this->fields
        ]));
    }

    /**
     * @param string $serialized
     * @throws ObfuscatedFormsException
     */
    public function unserialize($serialized)
    {
        $unserialize = unserialize(base64_decode($serialized));

        $name = $unserialize["name"] ?? null;
        if (!is_string($name) || !preg_match('/^\w{3,32}$/', $name)) {
            throw new ObfuscatedFormsException(
                sprintf('Serialized obfuscated form is incomplete or corrupt [%d]', __LINE__)
            );
        }

        $hash = $unserialize["hash"] ?? null;
        if (!is_string($hash) || !preg_match('/^[a-f0-9]{40}$/', $hash)) {
            throw new ObfuscatedFormsException(
                sprintf('Serialized obfuscated form is incomplete or corrupt [%d]', __LINE__)
            );
        }

        $fields = $unserialize["fields"];
        if (!is_array($fields)) {
            throw new ObfuscatedFormsException(
                sprintf('Serialized obfuscated form is incomplete or corrupt [%d]', __LINE__)
            );
        }

        $this->name = $name;
        $this->hash = $hash;
        $this->fields = $fields;
        $this->obfuscated = array_flip($fields);
        $this->count = count($fields);
    }

    /**
     * @param array $data
     * @return Form
     */
    public function input(array $data): self
    {
        $this->input = $data;
        return $this;
    }

    /**
     * @param string $field
     * @return null|string
     */
    public function key(string $field): ?string
    {
        return $this->fields[$field] ?? null;
    }

    /**
     * @param string $key
     * @return null|string
     */
    public function field(string $key): ?string
    {
        return $this->obfuscated[$key] ?? null;
    }

    /**
     * @param string $field
     * @return mixed|null
     * @throws ObfuscatedFormsException
     */
    public function value(string $field)
    {
        if (!is_array($this->input)) {
            throw new ObfuscatedFormsException('No input data has been defined');
        }

        $field = $this->fields[$field] ?? null;
        if ($field) {
            return $this->input[$field] ?? null;
        }

        return null;
    }

    /**
     * @return string
     */
    public function hash(): string
    {
        return $this->hash;
    }

    /**
     * @return string
     */
    public function name(): string
    {
        return $this->name;
    }
}