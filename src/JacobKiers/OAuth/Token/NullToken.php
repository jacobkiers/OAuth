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

namespace JacobKiers\OAuth\Token;

/**
 * Token holds the properties of a single token.
 *
 * This class deals with both temporary (request) and token (access) credntials.
 *
 * @package OAuth
 * @author Gary Jones <gary@garyjones.co.uk>
 */
class NullToken extends Token
{
    /**
     * Constructs a new Token object and populates the required parameters.
     *
     * @param string $key    Token key / identifier.
     * @param string $secret Token shared-secret.
     */
    public function __construct()
    {
        $this->setKey('');
        $this->setSecret('');
    }
}
