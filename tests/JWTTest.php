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

        $this->expectException(UnexpectedValueException::class);
        JWT::decode($bad, $keyring, array('HS256'));
    }
}
