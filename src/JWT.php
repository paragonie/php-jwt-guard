<?php
namespace ParagonIE\PhpJwtGuard;

use Firebase\JWT\JWT as FirebaseJwt;
use InvalidArgumentException;
use SodiumException;
use UnexpectedValueException;

class JWT extends FirebaseJwt
{
    /**
     * @param JWTKey|array|object $payload
     * @param resource|string $key
     * @param string $alg
     * @param null $keyId
     * @param null $head
     * @return string
     */
    public static function encode($payload, $key, $alg = 'HS256', $keyId = null, $head = null)
    {
        if ($key instanceof KeyRing) {
            if ($keyId) {
                throw new InvalidArgumentException('No key ID specified for a keyring');
            }
            $key = $key[$keyId];
        }
        if ($key instanceof JWTKey) {
            return parent::encode($payload, $key->getKeyMaterial(), $alg, $keyId, $head);
        }
        return parent::encode($payload, $key, $alg, $keyId, $head);
    }

    /**
     * @param string $jwt
     * @param KeyRing|JWTKey|array|resource|string $key
     * @param array $allowed_algs
     * @return object
     *
     * @throws SodiumException
     */
    public static function decode($jwt, $key, array $allowed_algs = array())
    {
        if (empty($key)) {
            throw new InvalidArgumentException('Key may not be empty');
        }
        if ($key instanceof KeyRing) {
            $tks = \explode('.', $jwt);
            if (\count($tks) != 3) {
                throw new UnexpectedValueException('Wrong number of segments');
            }
            $headb64 = $tks[0];
            if (null === ($header = static::jsonDecode(static::urlsafeB64Decode($headb64)))) {
                throw new UnexpectedValueException('Invalid header encoding');
            }

            if (isset($header->kid)) {
                if (!isset($key[$header->kid])) {
                    throw new UnexpectedValueException('"kid" invalid, unable to lookup correct key');
                }
                $key = $key[$header->kid];
            } else {
                throw new UnexpectedValueException('"kid" empty, unable to lookup correct key');
            }

            $alg_ok = false;
            foreach ($allowed_algs as $alg) {
                $alg_ok |= $key->isValidForAlg($alg);
            }
            if (!$alg_ok) {
                throw new UnexpectedValueException('Incorrect algorithm.');
            }

            return parent::decode($jwt, $key->getKeyMaterial(), $allowed_algs);
        } elseif (\is_array($key) || $key instanceof \ArrayAccess) {
            throw new UnexpectedValueException("Please switch to using KeyRings");
        }
        return parent::decode($jwt, $key, $allowed_algs);
    }
}
