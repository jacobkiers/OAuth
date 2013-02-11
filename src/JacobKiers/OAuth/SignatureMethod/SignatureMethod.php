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

namespace JacobKiers\OAuth\SignatureMethod;

use \JacobKiers\OAuth\Util;
use \JacobKiers\OAuth\Consumer\ConsumerInterface;
use \JacobKiers\OAuth\Token\TokenInterface;
use \JacobKiers\OAuth\Request\RequestInterface;

/**
 * A class for implementing a Signature Method.
 *
 * See section 9 ("Signing Requests") in the spec
 *
 * @package OAuth
 * @author Andy Smith
 * @author Gary Jones <gary@garyjones.co.uk>
 */
abstract class SignatureMethod implements SignatureMethodInterface
{
    /**
     * Return the name of the Signature Method (ie HMAC-SHA1).
     *
     * @return string
     */
    abstract public function getName();

    /**
     * Build up the signature.
     *
     * NOTE: The output of this function MUST NOT be urlencoded.
     * the encoding is handled in OAuthRequest when the final
     * request is serialized.
     *
     * @param JacobKiers\OAuth\Request\RequestInterface $request
     * @param JacobKiers\OAuth\Consumer\ConsumerInterface        $consumer
     * @param JacobKiers\OAuth\Token\TokenInterface     $token
     *
     * @return string
     */
    abstract public function buildSignature(RequestInterface $request, ConsumerInterface $consumer, TokenInterface $token = null);

    /**
     * Get the signature key, made up of consumer and optionally token shared secrets.
     *
     * @param JacobKiers\OAuth\Consumer\ConsumerInterface    $consumer
     * @param JacobKiers\OAuth\Token\TokenInterface $token
     *
     * @return string
     */
    public function getSignatureKey(ConsumerInterface $consumer, TokenInterface $token = null)
    {
        $key_parts = array(
            $consumer->getSecret(),
            ($token) ? $token->getSecret() : '',
        );

        $key_parts = Util::urlencodeRfc3986($key_parts);
        return implode('&', $key_parts);
    }

    /**
     * Verifies that a given signature is correct.
     *
     * @param JacobKiers\OAuth\Request\RequestInterface $request
     * @param JacobKiers\OAuth\Consumer\ConsumerInterface        $consumer
     * @param JacobKiers\OAuth\Token\TokenInterface     $token
     * @param string                                    $signature
     *
     * @return bool
     */
    public function checkSignature(RequestInterface $request, ConsumerInterface $consumer, TokenInterface $token, $signature)
    {
        $built = $this->buildSignature($request, $consumer, $token);
        return $built == $signature;
    }
}
