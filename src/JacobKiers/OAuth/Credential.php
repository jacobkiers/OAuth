<?php
/**
 * OAuth
 *
 * @package OAuth
 * @author Andy Smith
 * @author Gary Jones <gary@garyjones.co.uk>
 * @license https://raw.github.com/jacobkiers/OAuth/master/LICENSE MIT
 * @link https://github.com/jacobkiers/OAuth
 */

namespace JacobKiers\OAuth;

/**
 * Credential is the blueprint for all key + secret classes.
 *
 * @package OAuth
 * @author Gary Jones <gary@garyjones.co.uk>
 */
abstract class Credential
{
    /**
     * The credential key.
     *
     * @var string
     */
    protected $key;

    /**
     * The secret or shared-secret.
     *
     * @var string
     */
    protected $secret;

    /**
     * Return the credential key.
     *
     * @return string Credential key.
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * Set the credential key.
     *
     * @param string $key Credential identifier
     */
    public function setKey($key)
    {
        $this->key = $key;
    }

    /**
     * Return the credential secret
     *
     * @return string
     */
    public function getSecret()
    {
        return $this->secret;
    }

    /**
     * Set the credential key.
     *
     * @param string $key Credential identifier
     */
    public function setSecret($secret)
    {
        $this->secret = $secret;
    }
}
