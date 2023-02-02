<?php

declare(strict_types=1);

namespace Pandawa\Signature;

use BadMethodCallException;
use DateTime;
use DateTimeZone;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Http\Request;
use Pandawa\Signature\Contract\ClientInterface;
use Pandawa\Signature\Contract\ClientRepositoryInterface;

/**
 * @property ClientInterface $user
 *
 * @author  Iqbal Maulana <iq.bluejack@gmail.com>
 */
class SignatureGuard implements Guard
{
    use GuardHelpers;

    protected readonly Signer $signer;

    public function __construct(
        protected readonly ClientRepositoryInterface $clientRepository,
        protected readonly Request $request,
        protected readonly ?int $ttl = null,
        protected readonly string $algo = 'sha256',
    )
    {
        $this->signer = new Signer();
    }

    public function user(): ClientInterface
    {
        if (!is_null($this->user)) {
            return $this->user;
        }

        $this->validateRequest();

        return $this->user = $this->validateSignature(
            $this->getClaimForRequest()
        );
    }

    public function validate(array $credentials = []): bool
    {
        throw new BadMethodCallException('Validate is not supported in SignatureGuard.');
    }

    protected function validateSignature(Claim $claim): ClientInterface
    {
        $clientId = $this->request->header('Client-Id');

        if (null === $client = $this->clientRepository->findByClientId($clientId)) {
            throw new AuthenticationException(
                sprintf('Client id "%s" not found or disabled.', $clientId)
            );
        }

        $signature = $this->signer->sign($clientId, $client->getSecret(), $claim);

        if (!$signature->isValid($this->request)) {
            throw new AuthenticationException('Invalid signature.');
        }

        return $client;
    }

    protected function getClaimForRequest(): Claim
    {
        $request = $this->request;
        $requestTimestamp = new DateTime($request->header('Request-Timestamp'));
        $requestTimestamp->setTimezone(new DateTimeZone('UTC'));
        $requestBody = $request->getContent();

        return new Claim(
            '/' . $request->path(),
            $request->header('Request-Id'),
            $requestTimestamp,
            !empty($requestBody) ? $requestBody : null,
        );
    }

    protected function validateRequest(): void
    {
        $request = $this->request;
        $headers = [
            'Client-Id',
            'Request-Id',
            'Request-Timestamp',
            'Signature',
        ];

        foreach ($headers as $header) {
            if (empty($request->header($header))) {
                throw new AuthenticationException(
                    sprintf('Missing header "%s"', $header)
                );
            }
        }

        $requestTimestamp = DateTime::createFromFormat(
            'Y-m-d\TH:i:s\Z',
            $request->header('Request-Timestamp'),
            new DateTimeZone('UTC')
        );

        if (false === $requestTimestamp) {
            throw new AuthenticationException('Invalid value for header "Request-Timestamp"');
        }

        $this->validateTtl($requestTimestamp);
    }

    protected function validateTtl(DateTime $requestTimestamp): void
    {
        if (null !== $this->ttl) {
            $threshold = (clone $requestTimestamp)->modify(sprintf('+%d minutes', $this->ttl));
            $now = new DateTime('now', new DateTimeZone('UTC'));

            if ($now > $threshold) {
                throw new AuthenticationException('The given signature has been expired.');
            }
        }
    }
}
