<?php
/**
 * OAuth
 *
 * @package OAuth
 * @author Jacob Kiers <jacob@alphacomm.nl>
 * @license https://raw.github.com/jacobkiers/OAuth/master/LICENSE MIT
 * @link https://github.com/jacobkiers/OAuth
 */

namespace JacobKiers\OAuth\Request;

/**
 * Interface providing the necessary methods to handle an OAuth request.
 *
 * @package OAuth
 * @author Jacob Kiers <jacob@alphacomm.nl>
 */
interface RequestInterface
{
    /**
     * Returns the OAuth Callback parameter.
     *
     * @return string
     */
    public function getOAuthCallback();

    /**
     * Returns the Consumer Key.
     *
     * @return string
     */
    public function getOAuthConsumerKey();

    /**
     * Returns the Nonce.
     *
     * In combination with the timestamp and the token, the nonce is
     * used to prevent replay and side-channel attacks.
     *
     * @return string
     */
    public function getOAuthNonce();

    /**
     * Returns the request signature.
     *
     * @return string
     */
    public function getOAuthSignature();

    /**
     * Returns the base string of this request.
     *
     * The base string defined as the method, the url
     * and the parameters (normalized), each urlencoded
     * and the concated with &.
     *
     * @return string
     */
    public function getOAuthSignatureBaseString();

    /**
     * Returns the signature method with which this signature is signed.
     *
     * @return string
     */
    public function getOAuthSignatureMethod();

    /**
     * Returns the timestamp of the request.
     *
     * @return integer
     */
    public function getOAuthTimestamp();

    /**
     * Returns the token.
     *
     * @return string
     */
    public function getOAuthToken();

    /**
     * Returns the verifier.
     *
     * @return string
     */
    public function getOAuthVerifier();

    /**
     * Returns the OAuth version used in this request.
     *
     * @var string
     */
    public function getOAuthVersion();
}
