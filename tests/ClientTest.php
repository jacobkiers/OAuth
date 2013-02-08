<?php

use JacobKiers\OAuth\Client;

class ClientTest extends PHPUnit_Framework_TestCase
{
	public function testKeyAndSecretAreSet()
    {
        $client = new Client('foo', 'bar');
        $this->assertEquals('foo', $client->getKey());
        $this->assertEquals('bar', $client->getSecret());
    }

	public function testCallbackUrlIsSet()
    {
        $client = new Client('foo', 'bar', 'http://example.com/foobar');
        $this->assertEquals('http://example.com/foobar', $client->getCallbackUrl());
    }

}
