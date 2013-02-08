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
 * The RSA-SHA1 signature method.
 *
 * The RSA-SHA1 signature method uses the RSASSA-PKCS1-v1_5 signature algorithm as defined in
 * [RFC3447] section 8.2 (more simply known as PKCS#1), using SHA-1 as the hash function for
 * EMSA-PKCS1-v1_5. It is assumed that the Client has provided its RSA public key in a
 * verified way to the Service Provider, in a manner which is beyond the scope of this
 * specification.
 *   - Chapter 9.3 ("RSA-SHA1")
 *
 * @package OAuth
 * @author Andy Smith
 */
abstract class RsaSha1 extends SignatureMethod
{
    /**
     * Return the name of the Signature Method.
     *
     * @return string
     */
    public function getName()
    {
        return 'RSA-SHA1';
    }

    /**
     * Up to the SP to implement this lookup of keys. Possible ideas are:
     * (1) do a lookup in a table of trusted certs keyed off of client
     * (2) fetch via http using a url provided by the requester
     * (3) some sort of specific discovery code based on request
     *
     * Either way should return a string representation of the certificate
     *
     */
    abstract protected function fetchPublicCert(&$request);

    /**
     * Up to the SP to implement this lookup of keys. Possible ideas are:
     * (1) do a lookup in a table of trusted certs keyed off of client
     *
     * Either way should return a string representation of the certificate
     */
    abstract protected function fetchPrivateCert(&$request);

    /**
     * Build up the signature.
     *
     * @param JacobKiers\OAuth\Request $request
     * @param JacobKiers\OAuth\Client  $client
     * @param JacobKiers\OAuth\Token   $token
     *
     * @return string
     */
    public function buildSignature(Request $request, Client $client, Token $token = null)
    {
        $base_string = $request->getOAuthSignatureBaseString();

        // Fetch the private key cert based on the request
        $cert = $this->fetchPrivateCert($request);

        // Pull the private key ID from the certificate
        $privatekeyid = openssl_get_privatekey($cert);

        // Sign using the key
        $ok = openssl_sign($base_string, $signature, $privatekeyid);

        // Release the key resource
        openssl_free_key($privatekeyid);

        return base64_encode($signature);
    }

    /**
     * Verifies that a given signature is correct.
     *
     * @param JacobKiers\OAuth\Request  $request
     * @param JacobKiers\OAuth\Consumer $client
     * @param JacobKiers\OAuth\Token    $token
     * @param string                   $signature
     *
     * @return bool
     */
    public function checkSignature(Request $request, Client $client, Token $token, $signature)
    {
        $base_string = $request->getOAuthSignatureBaseString();

        $decoded_sig = base64_decode($signature);

        // Fetch the public key cert based on the request
        $cert = $this->fetchPublicCert($request);

        // Pull the public key ID from the certificate
        $publickeyid = openssl_get_publickey($cert);

        // Check the computed signature against the one passed in the query
        $ok = openssl_verify($base_string, $decoded_sig, $publickeyid);

        // Release the key resource
        openssl_free_key($publickeyid);

        return $ok == 1;
    }
}
