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

namespace JacobKiers\OAuth\Consumer;

use \JacobKiers\OAuth\Credential;

/**
 * Consumer holds the properties of a single Consumer / consumer.
 *
 * @package OAuth
 * @author Gary Jones <gary@garyjones.co.uk>
 */
class Consumer extends Credential implements ConsumerInterface
{
    /**
     * URL to which authorized requests will redirect to.
     *
     * @var string
     */
    protected $callback_url;

    /**
     * Constructs a new Consumer object and populates the required parameters.
     *
     * @param string $key          Consumer key / identifier.
     * @param string $secret       Consumer shared-secret.
     * @param string $callback_url URL to which authorized request will redirect to.
     */
    public function __construct($key, $secret, $callback_url = null)
    {
        $this->setKey($key);
        $this->setSecret($secret);
        $this->setCallbackUrl($callback_url);
    }

    /**
     * Get the callback URL.
     *
     * @return string
     */
    public function getCallbackUrl()
    {
        return $this->callback_url;
    }

    /**
     * Set the callbackURL
     *
     * @param string $callback_url
     */
    public function setCallbackUrl($callback_url)
    {
        $this->callback_url = $callback_url;
    }
}
