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
 * Group of static utility methods.
 *
 * @package OAuth
 * @author Andy Smith
 */
class Util
{
    /**
     * Encode a string according to RFC 3986.
     *
     * @param string $input
     *
     * @return string Encoded string.
     */
    public static function urlencodeRfc3986($input)
    {
        if (is_array($input)) {
            return array_map(array('JacobKiers\OAuth\Util', 'urlencodeRfc3986'), $input);
        } elseif (is_scalar($input)) {
            return str_replace('+', ' ', str_replace('%7E', '~', rawurlencode($input)));
        } else {
            return '';
        }
    }

    /**
     * Decode a string.
     *
     * This decode function isn't taking into consideration the above modifications to the encoding process.
     * However, this method doesn't seem to be used anywhere so leaving it as is.
     *
     * @param string $string
     *
     * @return string Decoded string.
     */
    public static function urldecodeRfc3986($string)
    {
        return urldecode($string);
    }

    /**
     * Utility function for turning the Authorization: header into parameters.
     *
     * Has to do some unescaping. Can filter out any non-oauth parameters if needed (default behaviour).
     *
     * May 28th, 2010 - method updated to tjerk.meesters for a speed improvement.
     *                  see http://code.google.com/p/oauth/issues/detail?id=163
     *
     * @param string $header
     * @param bool   $only_allow_oauth_parameters
     *
     * @return array
     */
    public static function splitHeader($header, $only_allow_oauth_parameters = true)
    {
        $params = array();
        $regex = '/(' . ($only_allow_oauth_parameters ? 'oauth_' : '') . '[a-z_-]*)=(:?"([^"]*)"|([^,]*))/';
        if (preg_match_all($regex, $header, $matches)) {
            foreach ($matches[1] as $i => $h) {
                $params[$h] = Util::urldecodeRfc3986(empty($matches[3][$i]) ? $matches[4][$i] : $matches[3][$i]);
            }
            if (isset($params['realm'])) {
                unset($params['realm']);
            }
        }
        return $params;
    }

    /**
     * Helper to try to sort out headers for people who aren't running apache
     *
     * @return array
     */
    public static function getHeaders()
    {
        $out = array();
        if (function_exists('apache_request_headers')) {
            // we need this to get the actual Authorization: header
            // because apache tends to tell us it doesn't exist
            $headers = apache_request_headers();

            // sanitize the output of apache_request_headers because
            // we always want the keys to be Cased-Like-This and arh()
            // returns the headers in the same case as they are in the
            // request
            foreach ($headers as $key => $value) {
                $key = str_replace(' ', '-', ucwords(strtolower(str_replace('-', ' ', $key))));
                $out[$key] = $value;
            }
        } else {
            // otherwise we don't have apache and are just going to have to hope
            // that $_SERVER actually contains what we need
            if (isset($_SERVER['CONTENT_TYPE'])) {
                $out['Content-Type'] = $_SERVER['CONTENT_TYPE'];
            }
            if (isset($_ENV['CONTENT_TYPE'])) {
                $out['Content-Type'] = $_ENV['CONTENT_TYPE'];
            }

            foreach ($_SERVER as $key => $value) {
                if (substr($key, 0, 5) == "HTTP_") {
                    // this is chaos, basically it is just there to capitalize the first
                    // letter of every word that is not an initial HTTP and strip HTTP
                    // code from przemek
                    $key = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($key, 5)))));
                    $out[$key] = $value;
                }
            }
        }
        return $out;
    }

    /**
     * Pull key=value querystring into an array.
     *
     * This function takes a input like a=b&a=c&d=e and returns the parsed
     * parameters like this
     * array('a' => array('b','c'), 'd' => 'e')
     *
     * @param string $input
     *
     * @return array
     */
    public static function parseParameters($input)
    {
        if (!isset($input) || !$input) {
            return array();
        }

        $pairs = explode('&', $input);

        $parsed_parameters = array();
        foreach ($pairs as $pair) {
            $split = explode('=', $pair, 2);
            $parameter = Util::urldecodeRfc3986($split[0]);
            $value = isset($split[1]) ? Util::urldecodeRfc3986($split[1]) : '';

            if (isset($parsed_parameters[$parameter])) {
                // We have already recieved parameter(s) with this name, so add to the list
                // of parameters with this name

                if (is_scalar($parsed_parameters[$parameter])) {
                    // This is the first duplicate, so transform scalar (string) into an array
                    // so we can add the duplicates
                    $parsed_parameters[$parameter] = array($parsed_parameters[$parameter]);
                }

                $parsed_parameters[$parameter][] = $value;
            } else {
                $parsed_parameters[$parameter] = $value;
            }
        }
        return $parsed_parameters;
    }

    /**
     * Build query string from parameters, with correct encoding.
     *
     * @param array $params
     *
     * @return string
     */
    public static function buildHttpQuery(array $params)
    {
        if (!$params) {
            return '';
        }

        // Urlencode both keys and values
        $keys = Util::urlencodeRfc3986(array_keys($params));
        $values = Util::urlencodeRfc3986(array_values($params));
        $params = array_combine($keys, $values);

        // Parameters are sorted by name, using lexicographical byte value ordering.
        // Ref: Spec: 9.1.1 (1)
        uksort($params, 'strcmp');

        $pairs = array();
        foreach ($params as $parameter => $value) {
            if (is_array($value)) {
                // If two or more parameters share the same name, they are sorted by their value
                // Ref: Spec: 9.1.1 (1)
                // June 12th, 2010 - changed to sort because of issue 164 by hidetaka
                sort($value, SORT_STRING);
                foreach ($value as $duplicate_value) {
                    $pairs[] = $parameter . '=' . $duplicate_value;
                }
            } else {
                $pairs[] = $parameter . '=' . $value;
            }
        }
        // For each parameter, the name is separated from the corresponding value by an '=' character (ASCII code 61)
        // Each name-value pair is separated by an '&' character (ASCII code 38)
        return implode('&', $pairs);
    }
}
