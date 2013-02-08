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
 * The actual implementation of validating and assigning tokens is left up to
 * the system using this library.
 *
 * @package OAuth
 * @author Gary Jones <gary@garyjones.co.uk>
 */
interface DataStoreInterface
{
    /**
     * Validate the client.
     *
     * @param string $client_key
     *
     * @return JacobKiers\OAuth\Client
     */
    public function lookupClient($client_key);

    /**
     * Validate a token.
     *
     * @param JacobKiers\OAuth\Client $client
     * @param JacobKiers\OAuth\Token  $token
     * @param string                 $token_type Request or access token
     *
     * @return JacobKiers\OAuth\Token
     */
    public function lookupToken(Client $client, Token $token, $token_type);

    /**
     * Validate that a nonce has not been used with the same timestamp before.
     *
     * @param JacobKiers\OAuth\Client $client
     * @param JacobKiers\OAuth\Token  $token
     * @param string                 $nonce
     * @param int                    $timestamp
     *
     * @return boolean
     */
    public function lookupNonce(Client $client, Token $token, $nonce, $timestamp);

    /**
     * Return a new token attached to this client.
     *
     * @param JacobKiers\OAuth\Client $client
     * @param string                 $callback URI to store as the post-authorization callback.
     *
     * @return JacobKiers\OAuth\Token
     */
    public function newRequestToken(Client $client, $callback = null);

    /**
     * Return a new access token attached to this consumer for the user
     * associated with this token if the request token is authorized.
     *
     * Should also invalidate the request token.
     *
     * @param JacobKiers\OAuth\Client $client
     * @param JacobKiers\OAuth\Token  $token
     * @param string                 $verifier
     *
     * @return JacobKiers\OAuth\Token
     */
    public function newAccessToken(Client $client, Token $token, $verifier = null);
}
