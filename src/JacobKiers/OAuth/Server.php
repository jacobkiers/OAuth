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
 * OAuth server.
 *
 * @package OAuth
 * @author Andy Smith
 */
class Server
{
    /**
     * Limit to which timestamp is accepted, in seconds.
     *
     * Requests older than now - this value, are rejected as possible replay attack.
     *
     * @var int
     */
    protected $timestamp_threshold = 300; // 5 minutes

    /**
     * OAuth version.
     *
     * @var string
     */
    protected $version = '1.0';

    /**
     * Supported signature methods.
     *
     * @var array
     */
    protected $signature_methods = array();

    /**
     * Data store object reference.
     *
     * @var JacobKiers\OAuth\DataStoreInterface
     */
    protected $data_store;

    /**
     * Construct OAuth server instance.
     *
     * @param JacobKiers\OAuth\DataStoreInterface $data_store
     */
    public function __construct(DataStoreInterface $data_store)
    {
        $this->data_store = $data_store;
    }

    /**
     * Add a supported signature method.
     *
     * @param JacobKiers\OAuth\SignatureMethod $signature_method
     */
    public function addSignatureMethod(SignatureMethod $signature_method)
    {
        $this->signature_methods[$signature_method->getName()] =
            $signature_method;
    }

    // high level functions

    /**
     * Process a temporary credential (request_token) request.
     *
     * Returns the request token on success
     *
     * @param JacobKiers\OAuth\RequestInterfaceInterface $request
     *
     * @return JacobKiers\OAuth\Token
     */
    public function fetchRequestToken(RequestInterface &$request)
    {
        $this->getVersion($request);

        $client = $this->getClient($request);

        // no token required for the initial token request
        $token = new NullToken;

        $this->checkSignature($request, $client, $token);

        // Rev A change
        $callback = $request->getOAuthCallback();

        return $this->data_store->newRequestToken($client, $callback);
    }

    /**
     * Process a post-authorization token (access_token) request.
     *
     * Returns the access token on success.
     *
     * @param JacobKiers\OAuth\RequestInterfaceInterface $request
     *
     * @return JacobKiers\OAuth\Token
     */
    public function fetchAccessToken(RequestInterface &$request)
    {
        $this->getVersion($request);

        $client = $this->getClient($request);

        // requires authorized request token
        $token = $this->getToken($request, $client, 'request');

        $this->checkSignature($request, $client, $token);

        // Rev A change
        $verifier = $request->getOAuthVerifier();

        return $this->data_store->newAccessToken($token, $client, $verifier);
    }

    /**
     * Verify an api call, checks all the parameters.
     *
     * @param JacobKiers\OAuth\RequestInterfaceInterface $request
     *
     * @return array Client and Token
     */
    public function verifyRequest(RequestInterface &$request)
    {
        $this->getVersion($request);
        $client = $this->getClient($request);
        $token = $this->getToken($request, $client, 'access');
        $this->checkSignature($request, $client, $token);
        return array($client, $token);
    }

    // Internals from here

    /**
     * Check that version is 1.0.
     *
     * @param JacobKiers\OAuth\RequestInterfaceInterface $request
     *
     * @return string
     *
     * @throws JacobKiers\OAuth\OAuthException
     */
    private function getVersion(RequestInterface &$request)
    {
        $version = $request->getOAuthVersion();
        if (!$version) {
            // Service Providers MUST assume the protocol version to be 1.0 if this parameter is not present.
            // Chapter 7.0 ("Accessing Protected Ressources")
            $version = '1.0';
        }
        if ($version !== $this->version) {
            throw new OAuthException("OAuth version '$version' not supported");
        }
        return $version;
    }

    /**
     * Get the signature method name, and if it is supported.
     *
     * @param JacobKiers\OAuth\RequestInterfaceInterface $request
     *
     * @return string Signature method name.
     *
     * @throws JacobKiers\OAuth\OAuthException
     */
    private function getSignatureMethod(RequestInterface $request)
    {
        $signature_method = $request instanceof RequestInterface ? $request->getOAuthSignatureMethod() : null;

        if (!$signature_method) {
            // According to chapter 7 ("Accessing Protected Resources") the signature-method
            // parameter is required, and we can't just fallback to PLAINTEXT
            throw new OAuthException('No signature method parameter. This parameter is required');
        }

        if (!in_array($signature_method, array_keys($this->signature_methods))) {
            throw new OAuthException(
                "Signature method '$signature_method' not supported, try one of the following: " .
                implode(", ", array_keys($this->signature_methods))
            );
        }
        return $this->signature_methods[$signature_method];
    }

    /**
     * Try to find the client for the provided request's client key.
     *
     * @param JacobKiers\OAuth\RequestInterfaceInterface $request
     *
     * @return JacobKiers\OAuth\Client
     *
     * @throws JacobKiers\OAuth\OAuthException
     */
    private function getClient(RequestInterface $request)
    {
        $client_key = $request instanceof RequestInterface ? $request->getOAuthConsumerKey() : null;

        if (!$client_key) {
            throw new OAuthException('Invalid client key');
        }

        $client = $this->data_store->lookupClient($client_key);
        if (!$client) {
            throw new OAuthException('Invalid client');
        }

        return $client;
    }

    /**
     * Try to find the token for the provided request's token key.
     *
     * @param JacobKiers\OAuth\RequestInterfaceInterface $request
     * @param JacobKiers\OAuth\Client  $client
     * @param string                   $token_type
     *
     * @return JacobKiers\OAuth\Token
     *
     * @throws JacobKiers\OAuth\OAuthException
     */
    private function getToken(RequestInterface $request, Client $client, $token_type = 'access')
    {
        $token_field = $request instanceof RequestInterface ? $request->getOAuthToken() : null;

        $token = $this->data_store->lookupToken($client, $token_type, $token_field);
        if (!$token) {
            throw new OAuthException("Invalid $token_type token: $token_field");
        }
        return $token;
    }

    /**
     * All-in-one function to check the signature on a request.
     *
     * Should determine the signature method appropriately
     *
     * @param JacobKiers\OAuth\RequestInterfaceInterface $request
     * @param JacobKiers\OAuth\Client  $client
     * @param JacobKiers\OAuth\Token   $token
     *
     * @throws JacobKiers\OAuth\OAuthException
     */
    private function checkSignature(RequestInterface $request, Client $client, Token $token)
    {
        // this should probably be in a different method
        $timestamp = $request instanceof RequestInterface ? $request->getOAuthTimestamp() : null;
        $nonce = $request instanceof RequestInterface ? $request->getOAuthNonce() : null;

        $this->checkTimestamp($timestamp);
        $this->checkNonce($client, $token, $nonce, $timestamp);

        $signature_method = $this->getSignatureMethod($request);

        $signature = $request->getOAuthSignature();
        $valid_sig = $signature_method->checkSignature($request, $client, $token, $signature);

        if (!$valid_sig) {
            throw new OAuthException('Invalid signature');
        }
    }

    /**
     * Check that the timestamp is new enough
     *
     * @param int $timestamp
     *
     * @throws JacobKiers\OAuth\OAuthException
     */
    private function checkTimestamp($timestamp)
    {
        if (!$timestamp) {
            throw new OAuthException('Missing timestamp parameter. The parameter is required');
        }

        // verify that timestamp is recentish
        $now = time();
        if (abs($now - $timestamp) > $this->timestamp_threshold) {
            throw new OAuthException("Expired timestamp, yours $timestamp, ours $now");
        }
    }

    /**
     * Check that the nonce is not repeated
     *
     * @param JacobKiers\OAuth\Client $client
     * @param JacobKiers\OAuth\Token  $token
     * @param string                 $nonce
     * @param int                    $timestamp
     *
     * @throws JacobKiers\OAuth\OAuthException
     */
    private function checkNonce(Client $client, Token $token, $nonce, $timestamp)
    {
        if (!$nonce) {
            throw new OAuthException('Missing nonce parameter. The parameter is required');
        }

        // verify that the nonce is uniqueish
        $found = $this->data_store->lookupNonce($client, $token, $nonce, $timestamp);
        if ($found) {
            throw new OAuthException('Nonce already used: ' . $nonce);
        }
    }
}
