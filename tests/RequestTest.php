<?php

use Mockery as m;
use JacobKiers\OAuth\Request\Request;

class RequestTest extends PHPUnit_Framework_TestCase
{
    public function tearDown()
    {
        m::close();
    }

    /**
     * @expectedException \JacobKiers\OAuth\OAuthException
     */
    public function testRequestThrowsExceptionWhenNoOAuthConsumerKeyIsPresent()
    {
        $request = new Request('POST', 'http://example.com', array());
    }
    public function testHttpMethodCanBeNormalized()
    {
        $request = new Request('foo', 'bar', array('oauth_consumer_key' => 'bar'));
        $this->assertEquals('FOO', $request->getNormalizedHttpMethod());
    }

    public function testHttpUrlCanBeNormalized()
    {
        $request = new Request('foo', 'bar', array('oauth_consumer_key' => 'bar'));
        $this->assertEquals('http://bar', $request->getNormalizedHttpUrl());
        $request = new Request('foo', 'example.com:80', array('oauth_consumer_key' => 'bar'));
        $this->assertEquals('http://example.com', $request->getNormalizedHttpUrl());
        $request = new Request('foo', 'example.com:81', array('oauth_consumer_key' => 'bar'));
        $this->assertEquals('http://example.com:81', $request->getNormalizedHttpUrl());
        $request = new Request('foo', 'https://example.com', array('oauth_consumer_key' => 'bar'));
        $this->assertEquals('https://example.com', $request->getNormalizedHttpUrl());
        $request = new Request('foo', 'https://example.com:443', array('oauth_consumer_key' => 'bar'));
        $this->assertEquals('https://example.com', $request->getNormalizedHttpUrl());
        $request = new Request('foo', 'http://example.com/foobar', array('oauth_consumer_key' => 'bar'));
        $this->assertEquals('http://example.com/foobar', $request->getNormalizedHttpUrl());
        $request = new Request('foo', 'example.org:80/foobar', array('oauth_consumer_key' => 'bar'));
        $this->assertEquals('http://example.org/foobar', $request->getNormalizedHttpUrl());
    }
}
