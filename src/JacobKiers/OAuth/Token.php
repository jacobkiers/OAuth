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
 * Token holds the properties of a single token.
 *
 * This class deals with both temporary (request) and token (access) credentials.
 *
 * @package OAuth
 * @author Gary Jones <gary@garyjones.co.uk>
 */
class Token extends Credential
{
    /**
     * Constructs a new client object and populates the required parameters.
     *
     * @param string $key    Client key / identifier.
     * @param string $secret Client shared-secret.
     */
    public function __construct($key, $secret)
    {
        $this->setKey($key);
        $this->setSecret($secret);
    }

    /**
     * Generates the basic string serialization of a token that a server
     * would respond to request_token and access_token calls with.
     *
     * @return string
     */
    public function toString()
    {
        return 'oauth_token=' . Util::urlencodeRfc3986($this->key) .
            '&oauth_token_secret=' . Util::urlencodeRfc3986($this->secret);
    }
}
