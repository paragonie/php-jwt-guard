<?php
namespace ParagonIE\PhpJwtGuard;

use ArrayAccess;
use RuntimeException;
use SodiumException;

class KeyRing implements ArrayAccess
{
    /** @var array<string, JWTKey> $mapping */
    private $mapping;

    /**
     * @param array<string, JWTKey> $mapping
     */
    public function __construct(array $mapping = array())
    {
        $this->mapping = $mapping;
    }

    /**
     * Count the number of keys in the keyring
     *
     * @return int
     */
    public function count()
    {
        return count($this->mapping);
    }

    /**
     * Obtain all the keys intended for a specific algorithm.
     *
     * @param string $alg
     * @return KeyRing
     * @throws SodiumException
     */
    public function partition($alg)
    {
        $out = new KeyRing();
        foreach ($this->mapping as $keyId => $key) {
            if ($key->isValidForAlg($alg)) {
                $out[$keyId] = $key;
            }
        }
        return $out;
    }

    public function withHS256($keyId, $rawKeyData)
    {
        return $this->with('HS256', $keyId, $rawKeyData);
    }

    public function withHS384($keyId, $rawKeyData)
    {
        return $this->with('HS384', $keyId, $rawKeyData);
    }

    public function withHS512($keyId, $rawKeyData)
    {
        return $this->with('HS512', $keyId, $rawKeyData);
    }

    public function withPS256($keyId, $rawKeyData)
    {
        return $this->with('PS256', $keyId, $rawKeyData);
    }

    public function withPS384($keyId, $rawKeyData)
    {
        return $this->with('PS384', $keyId, $rawKeyData);
    }

    public function withPS512($keyId, $rawKeyData)
    {
        return $this->with('PS512', $keyId, $rawKeyData);
    }

    public function withRS256($keyId, $rawKeyData)
    {
        return $this->with('RS256', $keyId, $rawKeyData);
    }

    public function withRS384($keyId, $rawKeyData)
    {
        return $this->with('RS384', $keyId, $rawKeyData);
    }

    public function withRS512($keyId, $rawKeyData)
    {
        return $this->with('RS512', $keyId, $rawKeyData);
    }

    public function with($alg, $keyId, $rawKeyData)
    {
        $this->mapping[$keyId] = new JWTKey($rawKeyData, $alg);
        return $this;
    }

    /**
     * @param string $keyId
     * @param JWTKey $key
     * @return $this
     */
    public function mapKeyId($keyId, JWTKey $key)
    {
        $this->mapping[$keyId] = $key;
        return $this;
    }

    /**
     * @param mixed $offset
     * @return bool
     */
    public function offsetExists($offset)
    {
        if (!is_string($offset)) {
            throw new RuntimeException('Type error: argument 1 must be a string');
        }
        return array_key_exists($offset, $this->mapping);
    }

    /**
     * @param mixed $offset
     * @return JWTKey
     */
    public function offsetGet($offset)
    {
        $value = $this->mapping[$offset];
        if (!($value instanceof JWTKey)) {
            throw new RuntimeException('Type error: return value not an instance of JWTKey');
        }
        return $value;
    }

    /**
     * @param string $offset
     * @param JWTKey $value
     */
    public function offsetSet($offset, $value)
    {
        if (!is_string($offset)) {
            throw new RuntimeException('Type error: argument 1 must be a string');
        }
        if (!($value instanceof JWTKey)) {
            throw new RuntimeException('Type error: argument 2 must be an instance of JWT');
        }
        $this->mapKeyId($offset, $value);
    }

    /**
     * @param string $offset
     */
    public function offsetUnset($offset)
    {
        if (!is_string($offset)) {
            throw new RuntimeException('Type error: argument 1 must be a string');
        }
        unset($this->mapping[$offset]);
    }
}
