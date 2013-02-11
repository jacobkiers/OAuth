<?php

use Mockery as m;
use JacobKiers\OAuth\SignatureMethod\PlainText;

class PlainTextTest extends PHPUnit_Framework_TestCase
{
    public function tearDown()
    {
        m::close();
    }

    public function testSignatureName()
    {
        $plaintext = $this->getSignatureMethod();
        $this->assertEquals('PLAINTEXT', $plaintext->getName());
    }

    public function testBuildSignatureWithoutToken()
    {
        // Create instance of class to test
        $plaintext = $this->getSignatureMethod();

        // Get mock objects
        $request = $this->getRequest();
        $client = $this->getConsumer();

        // Run method being tested
        $signature = $plaintext->buildSignature($request, $client);

        // Check results
        $this->assertEquals('secret&', $signature);
    }

    public function testBuildSignatureWithToken()
    {
        // Create instance of class to test
        $plaintext = $this->getSignatureMethod();

        // Get mock objects
        $request = $this->getRequest();
        $client = $this->getConsumer();
        $token = $this->getToken();

        // Run method being tested
        $signature = $plaintext->buildSignature($request, $client, $token);

        // Check results
        $this->assertEquals('secret&token_secret', $signature);
    }

    private function getSignatureMethod()
    {
        return new PlainText;
    }

    private function getRequest()
    {
        return m::mock('JacobKiers\OAuth\Request\Request');
    }

    private function getConsumer()
    {
        return m::mock('JacobKiers\OAuth\Consumer\Consumer', function ($mock) {
            $mock->shouldReceive('getSecret')->withNoArgs()->andReturn('secret')->once();
        });
    }

    private function getToken()
    {
        return m::mock('JacobKiers\OAuth\Token\Token', function ($mock) {
            $mock->shouldReceive('getSecret')->withNoArgs()->andReturn('token_secret');
        });
    }
}
