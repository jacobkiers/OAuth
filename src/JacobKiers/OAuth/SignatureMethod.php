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
 * A class for implementing a Signature Method.
 *
 * See section 9 ("Signing Requests") in the spec
 *
 * @package OAuth
 * @author Andy Smith
 * @author Gary Jones <gary@garyjones.co.uk>
 */
abstract class SignatureMethod
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
     * @param JacobKiers\OAuth\RequestInterface $request
     * @param JacobKiers\OAuth\Client  $client
     * @param JacobKiers\OAuth\Token   $token
     *
     * @return string
     */
    abstract public function buildSignature(RequestInterface $request, Client $client, Token $token = null);

    /**
     * Get the signature key, made up of client and optionally token shared secrets.
     *
     * @param JacobKiers\OAuth\Client  $client
     * @param JacobKiers\OAuth\Token   $token
     *
     * @return string
     */
    public function getSignatureKey(Client $client, Token $token = null)
    {
        $key_parts = array(
            $client->getSecret(),
            ($token) ? $token->getSecret() : '',
        );

        $key_parts = Util::urlencodeRfc3986($key_parts);
        return implode('&', $key_parts);
    }

    /**
     * Verifies that a given signature is correct.
     *
     * @param JacobKiers\OAuth\RequestInterface  $request
     * @param JacobKiers\OAuth\Consumer $client
     * @param JacobKiers\OAuth\Token    $token
     * @param string                   $signature
     *
     * @return bool
     */
    public function checkSignature(RequestInterface $request, Client $client, Token $token, $signature)
    {
        $built = $this->buildSignature($request, $client, $token);
        return $built == $signature;
    }
}
