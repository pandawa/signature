<?php

declare(strict_types=1);

namespace Pandawa\Signature;

use Illuminate\Http\Request;

/**
 * @author  Iqbal Maulana <iq.bluejack@gmail.com>
 */
class Signature
{
    public function __construct(
        public readonly string $token,
        public readonly string $clientId,
        public readonly Claim $claim,
    ) {
    }

    public function getHeaders(): array
    {
        return [
            'Request-Id'        => $this->claim->requestId,
            'Client-Id'         => $this->clientId,
            'Request-Timestamp' => $this->claim->getRequestDateTimeString(),
            'Signature'         => $this->encodeToken(),
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
        $requestSignature = $request->header('Signature');

        return substr($requestSignature, strpos($requestSignature, '=') + 1);
    }

    protected function encodeToken(): string
    {
        return 'HMAC' . strtoupper($this->claim->algo) . '=' . $this->token;
    }
}
