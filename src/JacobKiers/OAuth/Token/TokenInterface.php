<?php
/**
 * OAuth
 *
 * @package OAuth
 * @author Jacob Kiers <jacob@alphacomm.nl>
 * @license https://raw.github.com/jacobkiers/OAuth/master/LICENSE MIT
 * @link https://github.com/jacobkiers/OAuth
 */

namespace JacobKiers\OAuth\Token;

/**
 * Credential is the blueprint for all key + secret classes.
 *
 * @package OAuth
 * @author Jacob Kiers <jacob@alphacomm.nl>
 */
interface TokenInterface
{
    /**
     * Return the credential key.
     *
     * @return string Credential key.
     */
    public function getKey();

    /**
     * Return the credential secret
     *
     * @return string
     */
    public function getSecret();
}
