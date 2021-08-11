<?php

use PHPUnit\Framework\TestCase;
use ParagonIE\PhpJwtGuard\JWT;
use ParagonIE\PhpJwtGuard\JWTKey;
use ParagonIE\PhpJwtGuard\KeyRing;

class JWTTest extends TestCase
{
    public function testBackCompat()
    {
        $key = hash('sha256', 'phpunit-test-key-for-issue-351');
        $encode = JWT::encode(
            array('sub' => 'phpunit'),
            $key,
            'HS256'
        );
        $decode = JWT::decode($encode, $key, array('HS256'));
        $this->assertEquals('phpunit', $decode->sub);
    }

    public function hsKeyring()
    {
        $keyring = new KeyRing();
        $keyring['foo'] = new JWTKey(
            hash('sha256', 'phpunit-test-key-for-issue-351'),
            'HS256'
        );
        $keyring['bar'] = new JWTKey(
            hash('sha384', 'phpunit-test-key-for-issue-351'),
            'HS384'
        );
        $keyring['baz'] = new JWTKey(
            hash('sha512', 'phpunit-test-key-for-issue-351'),
            'HS512'
        );
        return array(
            array($keyring)
        );
    }

    /**
     * @dataProvider hsKeyring
     */
    public function testAlgoHardness(KeyRing $keyring)
    {
        $encode = JWT::encode(
            array('sub' => 'phpunit'),
            $keyring['foo'],
            'HS256',
            'foo' // Correct Key ID
        );
        $decode = JWT::decode($encode, $keyring, array('HS256'));
        $this->assertEquals('phpunit', $decode->sub);

        $bad = JWT::encode(
            array('sub' => 'phpunit'),
            $keyring['foo'],
            'HS256',
            'bar' // Incorrect Key ID
        );

        $fail = false;
        try {
            JWT::decode($bad, $keyring, array('HS256'));
            $fail = true;
        } catch (UnexpectedValueException $ex) {
        }
        $this->assertFalse($fail, 'Expected an exception; was disappointed');
    }

    public function testConfusion()
    {
        $hsKey = hash('sha256', 'phpunit-test-key-for-issue-351');

        $esPubkey = "-----BEGIN PUBLIC KEY-----\n" .
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9\n" .
            "q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==\n" .
            "-----END PUBLIC KEY-----";

        $keyring = new KeyRing();
        $keyring->with('HS256', 'foo', $hsKey);
        $keyring->with('ES256', 'bar', $esPubkey);

        $payload = array('sub' => 'phpunit');
        $token = JWT::encode($payload, $esPubkey, 'HS256', 'bar'); // wrong algo

        $fail = false;
        try {
            JWT::decode($token, $keyring, array('HS256', 'ES256'));
            $fail = true;
        } catch (UnexpectedValueException $ex) {
        }
        $this->assertFalse($fail, 'Expected an exception');
    }

    public function testEncode()
    {
        $keyring = new KeyRing();
        $keyring->with('HS256', 'foo', hash('sha256', 'phpunit-test-key-for-issue-351'));

        $payload = array('sub' => 'phpunit');
        $encoded = JWT::encode($payload, $keyring, 'HS256', 'foo'); // should not throw exception
        $this->assertIsString($encoded);
    }
}
