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

namespace JacobKiers\OAuth\Request;

use \JacobKiers\OAuth\Util;
use \JacobKiers\OAuth\OAuthException;
use \JacobKiers\OAuth\Token\TokenInterface;
use \JacobKiers\OAuth\Consumer\ConsumerInterface;

/**
 * Handle an OAuth request.
 *
 * @package OAuth
 * @author Andy Smith
 */
class Request implements RequestInterface
{
    /**
     * HTTP parameters.
     *
     * @var array
     */
    protected $parameters;

    /**
     * HTTP method - likely GET or POST.
     *
     * @var string HTTP method.
     */
    protected $http_method;

    /**
     * The URL the request was made to.
     *
     * @var string Request URL.
     */
    protected $http_url;

    /**
     * OAuth version.
     *
     * @var string
     */
    public static $version = '1.0';

    /**
     * Stream of POSTed file.
     *
     * @var string
     */
    public static $POST_INPUT = 'php://input';

    /**
     * Construct a Request object.
     *
     * @param string $http_method Request HTTP method.
     * @param string $http_url    Request URL.
     * @param array  $parameters  HTTP parameters.
     */
    public function __construct($http_method, $http_url, array $parameters = null)
    {
        if(!isset($parameters['oauth_consumer_key'])) {
            throw new OAuthException('You need a OAuth consumer key to proceed');
        }

        $parameters = ($parameters) ? $parameters : array();
        $this->parameters = array_merge(Util::parseParameters(parse_url($http_url, PHP_URL_QUERY)), $parameters);
        $this->http_method = $http_method;
        $this->http_url = $http_url;
    }

    /**
     * a
     */
    /**
     * Attempt to build up a request from what was passed to the server.
     *
     * @param string $http_method Request HTTP method.
     * @param string $http_url    Request URL.
     * @param array  $parameters  HTTP parameters.
     *
     * @return JacobKiers\OAuth\Request\RequestInterface
     */
    public static function fromRequest($http_method = null, $http_url = null, $parameters = null)
    {
        $scheme = (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] != 'on') ? 'http' : 'https';
        $http_url = ($http_url) ? $http_url : $scheme .
            '://' . $_SERVER['HTTP_HOST'] .
            ':' .
            $_SERVER['SERVER_PORT'] .
            $_SERVER['REQUEST_URI'];
        $http_method = ($http_method) ? $http_method : $_SERVER['REQUEST_METHOD'];

        // We weren't handed any parameters, so let's find the ones relevant to
        // this request.
        // If you run XML-RPC or similar you should use this to provide your own
        // parsed parameter-list
        if (!$parameters) {
            // Find request headers
            $request_headers = Util::getHeaders();

            // Parse the query-string to find GET parameters
            $parameters = Util::parseParameters($_SERVER['QUERY_STRING']);

            // It's a POST request of the proper content-type, so parse POST
            // parameters and add those overriding any duplicates from GET
            if ('POST' == $http_method
                && isset($request_headers['Content-Type'])
                && strstr($request_headers['Content-Type'], 'application/x-www-form-urlencoded')
            ) {
                $post_data = Util::parseParameters(
                    file_get_contents(self::$POST_INPUT)
                );
                $parameters = array_merge($parameters, $post_data);
            }

            // We have a Authorization-header with OAuth data. Parse the header
            // and add those overriding any duplicates from GET or POST
            if (isset($request_headers['Authorization']) &&
                substr($request_headers['Authorization'], 0, 6) == 'OAuth ') {
                $header_parameters = Util::splitHeader(
                    $request_headers['Authorization']
                );
                $parameters = array_merge($parameters, $header_parameters);
            }
        }

        return new Request($http_method, $http_url, $parameters);
    }

    /**
     * Helper function to set up the request.
     *
     * @param JacobKiers\OAuth\Consumer\ConsumerInterface    $consumer
     * @param JacobKiers\OAuth\Token\TokenInterface $token
     * @param string                                $http_method
     * @param string                                $http_url
     * @param array                                 $parameters
     *
     * @return JacobKiers\OAuth\Request\RequestInterface
     */
    public static function fromConsumerAndToken(
        ConsumerInterface $consumer,
        TokenInterface $token,
        $http_method,
        $http_url,
        array $parameters = null
    ) {
        $parameters = ($parameters) ? $parameters : array();
        $defaults = array(
            'oauth_nonce' => Request::generateNonce(),
            'oauth_timestamp' => Request::generateTimestamp(),
            'oauth_consumer_key' => $consumer->getKey());
        if ($token->getKey()) {
            $defaults['oauth_token'] = $token->getKey();
        }

        $parameters = array_merge($defaults, $parameters);

        return new Request($http_method, $http_url, $parameters);
    }

    /**
     * Add additional parameter to Request.
     *
     * @param string $name
     * @param string $value
     * @param bool   $allow_duplicates
     */
    public function setParameter($name, $value, $allow_duplicates = true)
    {
        if ($allow_duplicates && isset($this->parameters[$name])) {
            // We have already added parameter(s) with this name, so add to the list
            if (is_scalar($this->parameters[$name])) {
                // This is the first duplicate, so transform scalar (string)
                // into an array so we can add the duplicates
                $this->parameters[$name] = array($this->parameters[$name]);
            }

            $this->parameters[$name][] = $value;
        } else {
            $this->parameters[$name] = $value;
        }
    }

    /**
     * Get single request parameter by name.
     *
     * @param string $name
     *
     * @return string
     */
    public function getParameter($name)
    {
        return isset($this->parameters[$name]) ? $this->parameters[$name] : null;
    }

    /**
     * Get all request parameters.
     *
     * @return array
     */
    public function getParameters()
    {
        return $this->parameters;
    }

    /**
     * Unset single request parameter by name.
     *
     * @param string $name
     */
    public function unsetParameter($name)
    {
        unset($this->parameters[$name]);
    }

    /**
     * The request parameters, sorted and concatenated into a normalized string.
     *
     * @return string
     */
    public function getSignableParameters()
    {
        // Grab all parameters
        $params = $this->getParameters();

        // Remove oauth_signature if present
        // Ref: Spec: 9.1.1 ("The oauth_signature parameter MUST be excluded.")
        if (isset($params['oauth_signature'])) {
            unset($params['oauth_signature']);
        }

        return Util::buildHttpQuery($params);
    }

    /**
     * Returns the base string of this request
     *
     * The base string defined as the method, the url
     * and the parameters (normalized), each urlencoded
     * and the concated with &.
     *
     * @return string
     */
    public function getOAuthSignatureBaseString()
    {
        $parts = array(
            $this->getNormalizedHttpMethod(),
            $this->getNormalizedHttpUrl(),
            $this->getSignableParameters()
        );

        $encoded_parts = Util::urlencodeRfc3986($parts);

        return implode('&', $encoded_parts);
    }

    /**
     * Uppercases the HTTP method.
     *
     * @return string
     */
    public function getNormalizedHttpMethod()
    {
        return strtoupper($this->http_method);
    }

    /**
     * Parses the url and rebuilds it to be
     * scheme://host/path
     *
     * @return string URL
     */
    public function getNormalizedHttpUrl()
    {
        $parts = parse_url($this->http_url);

        $scheme = (isset($parts['scheme'])) ? $parts['scheme'] : 'http';
        $port = (isset($parts['port'])) ? $parts['port'] : '';
        if (isset($parts['host'])) {
            // parse_url in PHP 5.4.8 includes the port in the host, so we need to strip it.
            $host_and_maybe_port = explode(':', $parts['host']);
            $host = $host_and_maybe_port[0];
        } else {
            $host = '';
        }
        // For PHP 5.4+, use:
        // $host = (isset($parts['host'])) ? explode(':', $parts['host'])[0] : '';
        $path = (isset($parts['path'])) ? $parts['path'] : '';

        if ($port) {
            if (('https' == $scheme && $port != '443')
                || ('http' == $scheme && $port != '80')) {
                $host = "$host:$port";
            }
        }
        return "$scheme://$host$path";
    }

    /**
     * Builds a URL usable for a GET request.
     *
     * @return string
     */
    public function toUrl()
    {
        $post_data = $this->toPostdata();
        $out = $this->getNormalizedHttpUrl();
        if ($post_data) {
            $out .= '?' . $post_data;
        }
        return $out;
    }

    /**
     * Builds the data one would send in a POST request.
     *
     * @return string
     */
    public function toPostdata()
    {
        return Util::buildHttpQuery($this->getParameters());
    }

    /**
     * Builds the Authorization: header.
     *
     * @param string $realm Authorization realm.
     *
     * @return string
     *
     * @throws JacobKiers\OAuth\OAuthException
     */
    public function toHeader($realm = null)
    {
        $first = true;
        if ($realm) {
            $out = 'Authorization: OAuth realm="' . Util::urlencodeRfc3986($realm) . '"';
            $first = false;
        } else {
            $out = 'Authorization: OAuth';
        }

        $total = array();
        foreach ($this->parameters as $k => $v) {
            if (substr($k, 0, 5) != 'oauth') {
                continue;
            }
            if (is_array($v)) {
                throw new OAuthException('Arrays not supported in headers');
            }
            $out .= ($first) ? ' ' : ',';
            $out .= Util::urlencodeRfc3986($k) .
                '="' .
                Util::urlencodeRfc3986($v) .
                '"';
            $first = false;
        }
        return $out;
    }

    /**
     * Return request object cast as string.
     *
     * @return string
     */
    public function __toString()
    {
        return $this->toUrl();
    }

    /**
     * Build signature and add it as parameter.
     *
     * @param string                                $signature_method
     * @param JacobKiers\OAuth\Consumer\ConsumerInterface    $consumer
     * @param JacobKiers\OAuth\Token\TokenInterface $token
     */
    public function signRequest($signature_method, ConsumerInterface $consumer, TokenInterface $token)
    {
        $this->setParameter('oauth_signature_method', $signature_method->getName(), false);
        $signature = $this->buildSignature($signature_method, $consumer, $token);
        $this->setParameter('oauth_signature', $signature, false);
    }

    /**
     * Build signature.
     *
     * @param string                                $signature_method
     * @param JacobKiers\OAuth\Consumer\ConsumerInterface    $consumer
     * @param JacobKiers\OAuth\Token\TokenInterface $token
     *
     * @return string
     */
    public function buildSignature($signature_method, ConsumerInterface $consumer, TokenInterface $token)
    {
        return $signature_method->buildSignature($this, $consumer, $token);
    }

    /**
     * {@inheritdoc}
     */
    public function getOAuthCallback()
    {
        return $this->getParameter('oauth_callback');
    }

    /**
     * {@inheritdoc}
     */
    public function getOAuthConsumerKey()
    {
        return $this->getParameter('oauth_consumer_key');
    }

    /**
     * {@inheritdoc}
     */
    public function getOAuthNonce()
    {
        return $this->getParameter('oauth_nonce');
    }

    /**
     * {@inheritdoc}
     */
    public function getOAuthSignature()
    {
        return $this->getParameter('oauth_signature');
    }

    /**
     * {@inheritdoc}
     */
    public function getOAuthSignatureMethod()
    {
        return $this->getParameter('oauth_signature_method');
    }

    /**
     * {@inheritdoc}
     */
    public function getOAuthTimestamp()
    {
        return $this->getParameter('oauth_timestamp');
    }

    /**
     * {@inheritdoc}
     */
    public function getOAuthToken()
    {
        return $this->getParameter('oauth_token');
    }

    /**
     * {@inheritdoc}
     */
    public function getOAuthVerifier()
    {
        return $this->getParameter('oauth_verifier');
    }

    /**
     * {@inheritdoc}
     */
    public function getOAuthVersion()
    {
        return $this->getParameter('oauth_version');
    }


    /**
     * Get current time.
     *
     * @return int Timestamp.
     */
    private static function generateTimestamp()
    {
        return time();
    }

    /**
     * Generate nonce.
     *
     * @return string 32-character hexadecimal number.
     */
    private static function generateNonce()
    {
        return md5(microtime() . mt_rand()); // md5s look nicer than numbers
    }
}
