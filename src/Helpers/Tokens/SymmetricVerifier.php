<?php
declare(strict_types=1);

namespace Auth0\SDK\Helpers\Tokens;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;

/**
 * Class SymmetricVerifier
 *
 * @package Auth0\SDK\Helpers
 */
final class SymmetricVerifier extends SignatureVerifier
{
    /**
     * SymmetricVerifier constructor.
     *
     * @param string $clientSecret Client secret for the application.
     */
    public function __construct(string $clientSecret)
    {
        parent::__construct(new Signer\Hmac\Sha256());
        $this->setupJwtConfiguration($clientSecret);
    }

    /**
     * Check the token signature.
     *
     * @param Token $parsedToken Parsed token to check.
     *
     * @return boolean
     */
    protected function checkSignature(Token $parsedToken) : bool
    {
        return $this->doValidateSignature($parsedToken);
    }
}
