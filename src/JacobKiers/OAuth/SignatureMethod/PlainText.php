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

use \JacobKiers\OAuth\Consumer\ConsumerInterface;
use \JacobKiers\OAuth\Token\TokenInterface;
use \JacobKiers\OAuth\Request\RequestInterface;

/**
 * PLAINTEXT signature method.
 *
 * The PLAINTEXT method does not provide any security protection and SHOULD only be used
 * over a secure channel such as HTTPS. It does not use the Signature Base String.
 *   - Chapter 9.4 ("PLAINTEXT")
 *
 * @package OAuth
 * @author Andy Smith
 */
class PlainText extends SignatureMethod
{
    /**
     * Return the name of the Signature Method.
     *
     * @return string
     */
    public function getName()
    {
        return 'PLAINTEXT';
    }

    /**
     * Build up the signature.
     *
     * oauth_signature is set to the concatenated encoded values of the Consumer Secret and
     * Token Secret, separated by a '&' character (ASCII code 38), even if either secret is
     * empty. The result MUST be encoded again.
     *   - Chapter 9.4.1 ("Generating Signatures")
     *
     * Please note that the second encoding MUST NOT happen in the SignatureMethod, as
     * OAuthRequest handles this!
     *
     * @param JacobKiers\OAuth\Request\RequestInterface $request
     * @param JacobKiers\OAuth\Consumer\ConsumerInterface        $consumer
     * @param JacobKiers\OAuth\Token\TokenInterface     $token
     *
     * @return string
     */
    public function buildSignature(RequestInterface $request, ConsumerInterface $consumer, TokenInterface $token = null)
    {
        return $this->getSignatureKey($consumer, $token);
    }
}
