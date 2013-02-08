<?php

use Mockery as m;
use JacobKiers\OAuth\Request;

class RequestTest extends PHPUnit_Framework_TestCase
{
    public function tearDown()
    {
        m::close();
    }

    public function testHttpMethodCanBeNormalized()
    {
        $request = new Request('foo', 'bar');
        $this->assertEquals('FOO', $request->getNormalizedHttpMethod());
    }

    public function testHttpUrlCanBeNormalized()
    {
        $request = new Request('foo', 'bar');
        $this->assertEquals('http://bar', $request->getNormalizedHttpUrl());
        $request = new Request('foo', 'example.com:80');
        $this->assertEquals('http://example.com', $request->getNormalizedHttpUrl());
        $request = new Request('foo', 'example.com:81');
        $this->assertEquals('http://example.com:81', $request->getNormalizedHttpUrl());
        $request = new Request('foo', 'https://example.com');
        $this->assertEquals('https://example.com', $request->getNormalizedHttpUrl());
        $request = new Request('foo', 'https://example.com:443');
        $this->assertEquals('https://example.com', $request->getNormalizedHttpUrl());
        $request = new Request('foo', 'http://example.com/foobar');
        $this->assertEquals('http://example.com/foobar', $request->getNormalizedHttpUrl());
        $request = new Request('foo', 'example.org:80/foobar');
        $this->assertEquals('http://example.org/foobar', $request->getNormalizedHttpUrl());
    }
}
