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

namespace JacobKiers\OAuth\DataStore;

use \JacobKiers\OAuth\Token\TokenInterface;
use \JacobKiers\OAuth\Consumer\ConsumerInterface;

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
     * Validate the consumer.
     *
     * @param string $consumer_key
     *
     * @return JacobKiers\OAuth\Consumer\ConsumerInterface
     */
    public function lookupConsumer($consumer_key);

    /**
     * Validate a token.
     *
     * @param JacobKiers\OAuth\Consumer\ConsumerInterface $consumer
     * @param string                                      $token_type Request or access token
     * @param string                                      $token_key
     *
     * @return JacobKiers\OAuth\Token
     */
    public function lookupToken(ConsumerInterface $consumer, $token_type, $token_key);

    /**
     * Validate that a nonce has not been used with the same timestamp before.
     *
     * @param JacobKiers\OAuth\Consumer\ConsumerInterface $consumer
     * @param JacobKiers\OAuth\Token                      $token
     * @param string                                      $nonce
     * @param int                                         $timestamp
     *
     * @return boolean
     */
    public function lookupNonce(ConsumerInterface $consumer, TokenInterface $token, $nonce, $timestamp);

    /**
     * Return a new token attached to this consumer.
     *
     * @param JacobKiers\OAuth\Consumer\ConsumerInterface $consumer
     * @param string                                      $callback URI to send the post-authorisation callback to.
     *
     * @return JacobKiers\OAuth\Token
     */
    public function newRequestToken(ConsumerInterface $consumer, $callback = null);

    /**
     * Return a new access token attached to this consumer for the user
     * associated with this token if the request token is authorized.
     *
     * Should also invalidate the request token.
     *
     * @param JacobKiers\OAuth\Consumer\ConsumerInterface $consumer
     * @param JacobKiers\OAuth\Token                      $token
     * @param string                                      $verifier
     *
     * @return JacobKiers\OAuth\Token
     */
    public function newAccessToken(ConsumerInterface $consumer, TokenInterface $token, $verifier = null);
}
