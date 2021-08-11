<?php
namespace ParagonIE\PhpJwtGuard;

use Firebase\JWT\JWT as FirebaseJwt;
use InvalidArgumentException;
use SodiumException;
use UnexpectedValueException;

class JWT extends FirebaseJwt
{
    /**
     * @link FirebaseJwt::encode()
     *
     * @param JWTKey|array|object $payload
     * @param resource|string $key
     * @param string $alg
     * @param null $keyId
     * @param null $head
     * @return string
     *
     * @throws SodiumException
     */
    public static function encode($payload, $key, $alg = 'HS256', $keyId = null, $head = null)
    {
        if ($key instanceof KeyRing) {
            if (!$keyId) {
                throw new InvalidArgumentException('No key ID specified for a keyring');
            }

            // Partition the set of keys by the algorithm selected.
            $key = $key->partition($alg);
            if (empty($key[$keyId])) {
                throw new InvalidArgumentException('Key not found (or wrong algorithm)');
            }
            $key = $key[$keyId];
        }
        if ($key instanceof JWTKey) {
            return parent::encode($payload, $key->getKeyMaterial(), $alg, $keyId, $head);
        }
        return parent::encode($payload, $key, $alg, $keyId, $head);
    }

    /**
     * @link FirebaseJwt::decode()
     *
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

            // Partition the set of keys by the algorithm selected.
            $key = $key->partition($header->alg);

            if (isset($header->kid)) {
                if (!isset($key[$header->kid])) {
                    throw new UnexpectedValueException(
                        '"kid" invalid, unable to lookup correct key for given algorithm'
                    );
                }
                $key = $key[$header->kid];
            } else {
                throw new UnexpectedValueException('"kid" empty, unable to lookup correct key');
            }

            return parent::decode($jwt, $key->getKeyMaterial(), $allowed_algs);
        } elseif (\is_array($key) || $key instanceof \ArrayAccess) {
            throw new UnexpectedValueException("Please switch to using KeyRings");
        }
        return parent::decode($jwt, $key, $allowed_algs);
    }
}
