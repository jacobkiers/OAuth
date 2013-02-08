<?php

use Mockery as m;
use JacobKiers\OAuth\SignatureMethod;

/**
 * Create concrete class from abstract SignatureMethod.
 *
 * Have to define two methods which are abstract in SignatureMethod.
 */
class FooBarSignatureMethod extends SignatureMethod
{
    public function getName() {
    }

    public function buildSignature(
        \JacobKiers\OAuth\RequestInterface $request,
        \JacobKiers\OAuth\Client $client,
        \JacobKiers\OAuth\Token $token = null
    ) {
    }
}

class SignatureTest extends PHPUnit_Framework_TestCase
{
    public function tearDown()
    {
        m::close();
    }

    public function testGetSignatureKeyWithoutToken()
    {
        // Create instance of class to test, with mock objects passed in.
        $signature_method = $this->getSignatureMethod();

        // Get mock objects
        $client = $this->getClient();

        // Run method being tested
        $signature_key = $signature_method->getSignatureKey($client);

        // Check results
        $this->assertEquals('secret&', $signature_key);
    }

    public function testGetSignatureKeyWithToken()
    {
        // Create instance of class to test, with mock objects passed in.
        $signature_method = $this->getSignatureMethod();

        // Get mock objects
        $client = $this->getClient();
        $token = $this->getToken();

        // Run method being tested
        $signature_key = $signature_method->getSignatureKey($client, $token);

        // Check results
        $this->assertEquals('secret&token_secret', $signature_key);
    }

    private function getSignatureMethod()
    {
        return new FooBarSignatureMethod;
    }

    private function getClient()
    {
        return m::mock('JacobKiers\OAuth\Client', function ($mock) {
            $mock->shouldReceive('getSecret')->withNoArgs()->andReturn('secret')->once();
        });
    }

    private function getToken()
    {
        return m::mock('JacobKiers\OAuth\Token', function ($mock) {
            $mock->shouldReceive('getSecret')->withNoArgs()->andReturn('token_secret');
        });
    }
}
