<?php
declare(strict_types=1);

namespace Auth0\SDK\Helpers\Tokens;

use Auth0\SDK\Exception\InvalidTokenException;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\Token\UnsupportedHeaderFound;
use Lcobucci\JWT\Validation\Constraint\SignedWith;

/**
 * Class SignatureVerifier
 *
 * @package Auth0\SDK\Helpers
 */
abstract class SignatureVerifier
{
    /**
     * @var Configuration
     */
    protected $configuration;

    /**
     * @var Signer
     */
    protected $signer;

    /**
     * @var Token\Parser
     */
    protected $tokenParser;

    /**
     * SignatureVerifier constructor.
     *
     * @param Signer $signer
     */
    public function __construct(Signer $signer)
    {
        $this->signer = $signer;
        $this->tokenParser = new Token\Parser(new JoseEncoder());
    }

    /**
     * Check the token's signature.
     *
     * @param Token $parsedToken Parsed token to check.
     *
     * @return boolean
     */
    abstract protected function checkSignature(Token $parsedToken) : bool;

    /**
     * Format, algorithm, and signature checks.
     *
     * @param string $token Raw JWT ID token.
     *
     * @return Token\Plain
     *
     * @throws InvalidTokenException If JWT format is incorrect.
     * @throws InvalidTokenException If token algorithm does not match the validator.
     * @throws InvalidTokenException If token algorithm signature cannot be validated.
     */
    final public function verifyAndDecode(string $token) : Token\Plain
    {
        try {
            $parsedToken = $this->tokenParser->parse($token);
        } catch (UnsupportedHeaderFound | InvalidTokenStructure $e) {
            throw new InvalidTokenException( 'ID token could not be decoded' );
        }

        if (! $parsedToken instanceof Token\Plain) {
            throw new InvalidTokenException( 'ID token could not be decoded' );
        }

        $tokenAlg = $parsedToken->headers()->get('alg', false);
        if ($tokenAlg !== $this->signer->algorithmId()) {
            throw new InvalidTokenException( sprintf(
                'Signature algorithm of "%s" is not supported. Expected the ID token to be signed with "%s".',
                $tokenAlg,
                $this->signer->algorithmId()
            ));
        }

        if (! $this->checkSignature($parsedToken)) {
            throw new InvalidTokenException('Invalid ID token signature');
        }

        return $parsedToken;
    }

    protected function setupJwtConfiguration(string $strKey): void
    {
        $key = Key\InMemory::plainText($strKey);
        $this->configuration = Configuration::forSymmetricSigner($this->signer, $key);
        $this->configuration->setParser($this->tokenParser);
        $this->configuration->setValidationConstraints(
            new SignedWith($this->configuration->signer(), $this->configuration->signingKey())
        );
    }

    protected function doValidateSignature(Token $parsedToken): bool
    {
        return $this->configuration->validator()->validate(
            $parsedToken,
            new SignedWith($this->configuration->signer(), $this->configuration->signingKey())
        );
    }
}
