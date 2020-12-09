<?php
declare(strict_types=1);

namespace Auth0\SDK\Helpers\Tokens;

use Auth0\SDK\Exception\InvalidTokenException;
use Auth0\SDK\Helpers\JWKFetcher;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;

/**
 * Class AsymmetricVerifier
 *
 * @package Auth0\SDK\Helpers
 */
final class AsymmetricVerifier extends SignatureVerifier
{
    /**
     * Array of kid => keys or a JWKFetcher instance.
     *
     * @var array|JWKFetcher
     */
    private $jwks;

    /**
     * JwksVerifier constructor.
     *
     * @param array|JWKFetcher $jwks Array of kid => keys or a JWKFetcher instance.
     */
    public function __construct($jwks)
    {
        $this->jwks = $jwks;
        parent::__construct(new Signer\Rsa\Sha256());
    }

    /**
     * Check the token kid and signature.
     *
     * @param Token $parsedToken Parsed token to check.
     *
     * @return boolean
     *
     * @throws InvalidTokenException If ID token kid was not found in the JWKS.
     */
    protected function checkSignature(Token $parsedToken) : bool
    {
        $tokenKid   = $parsedToken->headers()->get('kid', false);
        $signingKey = is_array( $this->jwks ) ? ($this->jwks[$tokenKid] ?? null) : $this->jwks->getKey($tokenKid);

        if (! $signingKey) {
            throw new InvalidTokenException( 'ID token key ID "'.$tokenKid.'" was not found in the JWKS' );
        }

        $this->setupJwtConfiguration($signingKey);
        return $this->configuration->validator()->validate($parsedToken);
    }
}
