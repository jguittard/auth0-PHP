<?php
declare(strict_types=1);

namespace Auth0\SDK\Helpers\Tokens;

use Auth0\SDK\Exception\InvalidTokenException;
use DateTimeImmutable;
use Lcobucci\JWT\Token\RegisteredClaims;

/**
 * Class TokenVerifier, a generic JWT verifier.
 * For verifying OIDC-compliant ID tokens, use Auth0\SDK\Helpers\Tokens\IdTokenVerifier
 *
 * @package Auth0\SDK\Helpers\Tokens
 */
class TokenVerifier
{

    /**
     * Token issuer base URL expected.
     *
     * @var string
     */
    protected $issuer;

    /**
     * Token audience expected.
     *
     * @var string
     */
    protected $audience;

    /**
     * Token signature verifier.
     *
     * @var SignatureVerifier
     */
    private $verifier;

    /**
     * Clock tolerance for time-base token checks in seconds.
     *
     * @var integer
     */
    protected $leeway = 60;

    /**
     * TokenVerifier constructor.
     *
     * @param string            $issuer   Token issuer base URL expected.
     * @param string            $audience Token audience expected.
     * @param SignatureVerifier $verifier Token signature verifier.
     */
    public function __construct(string $issuer, string $audience, SignatureVerifier $verifier)
    {
        $this->issuer   = $issuer;
        $this->audience = $audience;
        $this->verifier = $verifier;
    }

    /**
     * Set a new leeway time for all token checks.
     *
     * @param integer $newLeeway New leeway time for class instance.
     *
     * @return void
     */
    public function setLeeway(int $newLeeway) : void
    {
        $this->leeway = $newLeeway;
    }

    /**
     * Verifies and decodes a JWT.
     *
     * @param string $token   Raw JWT string.
     * @param array  $options Options to adjust the verification. Can be:
     *      - "leeway" clock tolerance in seconds for the current check only. See $leeway above for default.
     *
     * @return array
     *
     * @throws InvalidTokenException Thrown if:
     *      - Token is missing (expected but none provided)
     *      - Signature cannot be verified
     *      - Token algorithm is not supported
     *      - Any claim-based test fails
     */
    public function verify(string $token, array $options = []) : array
    {
        if (empty($token)) {
            throw new InvalidTokenException('ID token is required but missing');
        }

        $verifiedToken = $this->verifier->verifyAndDecode( $token );

        /*
         * Issuer checks
         */

        if (! $verifiedToken->claims()->has(RegisteredClaims::ISSUER)) {
            throw new InvalidTokenException('Issuer (iss) claim must be a string present in the ID token');
        }

        if (! $verifiedToken->hasBeenIssuedBy($this->issuer)) {
            throw new InvalidTokenException( sprintf(
                'Issuer (iss) claim mismatch in the ID token; expected "%s", found "%s"', $this->issuer, $tokenIss
            ) );
        }

        /*
         * Audience checks
         */

        if (! $verifiedToken->claims()->has(RegisteredClaims::AUDIENCE)) {
            throw new InvalidTokenException(
                'Audience (aud) claim must be a string or array of strings present in the ID token'
            );
        }

        if (! $verifiedToken->isPermittedFor($this->audience)) {
            throw new InvalidTokenException( sprintf(
                'Audience (aud) claim mismatch in the ID token; expected "%s", found "%s"',
                $this->audience,
                $verifiedToken->claims()->get(RegisteredClaims::AUDIENCE)
            ));
        }

        /*
         * Clock checks
         */

        $now = new DateTimeImmutable();
        $now->setTimestamp(($options['time'] ?? time()) + ($options['leeway'] ?? $this->leeway));

        if (! $verifiedToken->claims()->has(RegisteredClaims::EXPIRATION_TIME)) {
            throw new InvalidTokenException('Expiration Time (exp) claim must be a number present in the ID token');
        }

        if ($verifiedToken->isExpired($now)) {
            throw new InvalidTokenException( sprintf(
                'Expiration Time (exp) claim error in the ID token; current time (%d) is after expiration time (%d)',
                $now->getTimestamp(),
                $verifiedToken->claims()->get(RegisteredClaims::EXPIRATION_TIME)->getTimestamp()
            ) );
        }

        return $verifiedToken->claims()->all();
    }
}
