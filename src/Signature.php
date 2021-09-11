<?php

declare(strict_types=1);

namespace Pandawa\Signature;

use Illuminate\Http\Request;

/**
 * @author  Iqbal Maulana <iq.bluejack@gmail.com>
 */
class Signature
{
    protected string $token;
    protected string $clientId;
    protected Claim $claim;

    public function __construct(string $token, string $clientId, Claim $claim)
    {
        $this->token = $token;
        $this->clientId = $clientId;
        $this->claim = $claim;
    }

    public function getToken(): string
    {
        return $this->token;
    }

    public function getHeaders(): array
    {
        return [
            'Client-Id'         => $this->clientId,
            'Request-Timestamp' => $this->claim->getRequestDateString(),
            'Signature'         => 'HMACSHA256='.$this->token,
        ];
    }

    public function isValid(Request $request): bool
    {
        $requestSignature = $this->extractSignature($request);

        return $requestSignature === $this->token;
    }

    public function __toString(): string
    {
        return $this->token;
    }

    protected function extractSignature(Request $request): string
    {
        $requestSignature = $request->header('signature');

        return substr($requestSignature, strpos($requestSignature, '=') + 1);
    }
}
