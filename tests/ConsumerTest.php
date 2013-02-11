<?php

use JacobKiers\OAuth\Consumer\Consumer;

class ConsumerTest extends PHPUnit_Framework_TestCase
{
    public function testKeyAndSecretAreSet()
    {
        $consumer = new consumer('foo', 'bar');
        $this->assertEquals('foo', $consumer->getKey());
        $this->assertEquals('bar', $consumer->getSecret());
    }

    public function testCallbackUrlIsSet()
    {
        $consumer = new consumer('foo', 'bar', 'http://example.com/foobar');
        $this->assertEquals('http://example.com/foobar', $consumer->getCallbackUrl());
    }

}
