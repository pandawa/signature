<?php

declare(strict_types=1);

namespace Pandawa\Signature\Middleware;

use DateTimeZone;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Validation\Factory;
use Illuminate\Http\Request;
use Pandawa\Signature\Claim;
use Pandawa\Signature\Contract\ClientRepository;
use Pandawa\Signature\Signer;
use Closure;
use DateTime;

/**
 * @author  Iqbal Maulana <iq.bluejack@gmail.com>
 */
class SignatureMiddleware
{
    protected ClientRepository $clientRepository;
    protected Signer $signer;
    protected Factory $validationFactory;

    public function __construct(ClientRepository $clientRepository, Signer $signer, Factory $validationFactory)
    {
        $this->clientRepository = $clientRepository;
        $this->signer = $signer;
        $this->validationFactory = $validationFactory;
    }

    public function handle(Request $request, Closure $next)
    {
        $this->validateRequest($request);

        $clientId = $request->header('Client-Id');

        if (null === $client = $this->clientRepository->findByClientId($clientId)) {
            throw new AuthenticationException('Undefined client');
        }

        $signature = $this->signer->sign($clientId, $client->getSecret(), $this->makeClaim($request));

        if (!$signature->isValid($request)) {
            throw new AuthenticationException('Invalid signature');
        }

        return $next($request);
    }

    protected function makeClaim(Request $request): Claim
    {
        $requestTimestamp = new DateTime($request->header('Request-Timestamp'));
        $requestTimestamp->setTimezone(new DateTimeZone('UTC'));
        $requestBody = $request->getContent();

        return new Claim(
            $request->header('Request-Id'),
            '/' . $request->path(),
            $requestTimestamp,
            !empty($requestBody) ? $requestBody : null,
        );
    }

    protected function validateRequest(Request $request): void
    {
        $headers = [
            'Client-Id',
            'Request-Id',
            'Request-Timestamp',
            'Signature',
        ];

        foreach ($headers as $header) {
            if (empty($request->header($header))) {
                throw new AuthenticationException(sprintf('Missing header "%s"', $header));
            }
        }

        $requestTimestamp = $request->header('Request-Timestamp');

        if (false === DateTime::createFromFormat('Y-m-d\TH:i:s\Z', $requestTimestamp)) {
            throw new AuthenticationException('Invalid header "Request-Timestamp"');
        }
    }
}
