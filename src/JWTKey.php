<?php

namespace ParagonIE\PhpJwtGuard;

use SodiumException;
use UnexpectedValueException;

class JWTKey
{
    /** @var string $alg */
    private $alg;

    /** @var string $keyMaterial */
    private $keyMaterial;

    /**
     * @param string $keyMaterial
     * @param string|array|null $alg
     */
    public function __construct($keyMaterial, $alg = null)
    {
        if (is_array($alg) || is_null($alg)) {
            throw new UnexpectedValueException("Algorith must be specified");
        }
        $this->keyMaterial = $keyMaterial;
        $this->alg = $alg;
    }

    /**
     * Is the header algorithm valid for this key?
     *
     * @param string $headerAlg
     * @return bool
     *
     * @throws SodiumException
     */
    public function isValidForAlg($headerAlg)
    {
        return sodium_memcmp($this->alg, $headerAlg) === 0;
    }

    /**
     * @return string
     */
    public function getKeyMaterial()
    {
        return $this->keyMaterial;
    }
}
