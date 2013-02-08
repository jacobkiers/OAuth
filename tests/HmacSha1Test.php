<?php

use Mockery as m;
use JacobKiers\OAuth\HmacSha1;

class HmacSha1Test extends PHPUnit_Framework_TestCase
{
    public function tearDown()
    {
        m::close();
    }

    public function testSignatureName()
    {
        $hmacsha1 = $this->getSignatureMethod();
        $this->assertEquals('HMAC-SHA1', $hmacsha1->getName());
    }

    public function testBuildSignatureWithoutToken()
    {
        // Create instance of class to test
        $hmacsha1 = $this->getSignatureMethod();

        // Get mock objects
        $request = $this->getRequest();
        $client = $this->getClient();

        // Run method being tested
        $signature = $hmacsha1->buildSignature($request, $client);

        // Check results
        $this->assertEquals('RaZU4UG/wwJ/E5Df2/pePmwaS1Q=', $signature);
    }

    public function testBuildSignatureWithToken()
    {
        // Create instance of class to test
        $hmacsha1 = $this->getSignatureMethod();

        // Get mock objects
        $request = $this->getRequest();
        $client = $this->getClient();
        $token = $this->getToken();

        // Run method being tested
        $signature = $hmacsha1->buildSignature($request, $client, $token);

        // Check results
        $this->assertEquals('1P/rfHzjnxBcNzngW9BEuT01goM=', $signature);
    }

    private function getSignatureMethod()
    {
        return new HmacSha1;
    }

    private function getRequest()
    {
        return m::mock('JacobKiers\OAuth\Request', function ($mock) {
            $mock->shouldReceive('getOAuthSignatureBaseString')
                ->withNoArgs()
                ->andReturn('POST&http%3A%2F%2Fexample.com%2Ffoobar&oauth_signature_method%3DHMAC-SHA1')->once();
        });
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
