<?php
/**
 * OAuth
 *
 * @package OAuth
 * @author Jacob Kiers <jacob@alphacomm.nl>
 * @license https://raw.github.com/jacobkiers/OAuth/master/LICENSE MIT
 * @link https://github.com/jacobkiers/OAuth
 */

namespace JacobKiers\OAuth\Consumer;

/**
 * Consumer holds the properties of a single Consumer / consumer.
 *
 * @package OAuth
 * @author Jacob Kiers <jacob@alphacomm.nl>
 */
interface ConsumerInterface
{
    /**
     * Get the callback URL.
     *
     * @return string
     */
    public function getCallbackUrl();

    /**
     * Set the callbackURL
     *
     * @param string $callback_url
     */
    public function setCallbackUrl($callback_url);

    /**
     * Return the Consumer key.
     *
     * @return string Consumer key.
     */
    public function getKey();

    /**
     * Return the Consumer secret
     *
     * @return string
     */
    public function getSecret();
}
