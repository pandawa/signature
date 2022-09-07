<?php

declare(strict_types=1);

namespace Pandawa\Signature;

use DateTime;
use DateTimeZone;
use Illuminate\Support\Str;

/**
 * @author  Iqbal Maulana <iq.bluejack@gmail.com>
 */
class Claim
{
    public readonly ?string $requestId;
    public readonly ?DateTime $requestDateTime;

    public function __construct(
        public readonly string $targetPath,
        ?string $requestId = null,
        ?DateTime $requestDateTime = null,
        public readonly ?string $body = null,
        public readonly string $algo = 'sha256',
    ) {
        if (null === $requestId) {
            $this->requestId = $this->generateRequestId();
        }

        if (null === $requestDateTime) {
            $this->requestDateTime = $this->generateDateTime();
        }
    }

    public function refresh(): static
    {
        return $this->refreshRequestId()->refreshRequestDataTime();
    }

    public function refreshRequestId(): static
    {
        return new static(
            $this->targetPath,
            $this->generateRequestId(),
            $this->requestDateTime,
            $this->body,
            $this->algo
        );
    }

    public function refreshRequestDataTime(): static
    {
        return new static(
            $this->targetPath,
            $this->requestId,
            $this->generateDateTime(),
            $this->body,
            $this->algo
        );
    }

    public function getRequestDateTimeString(): string
    {
        $date = $this->requestDateTime->format('c');

        return substr($date, 0, strpos($date, '+')) . 'Z';
    }

    public function getDigest(): ?string
    {
        if (null === $this->body) {
            return null;
        }

        return base64_encode(hash($this->algo, $this->body, true));
    }

    public function toArray(): array
    {
        return array_filter([
            $this->requestId,
            $this->getRequestDateTimeString(),
            $this->targetPath,
            $this->getDigest(),
        ]);
    }

    protected function generateRequestId(): string
    {
        return (string) Str::uuid();
    }

    protected function generateDateTime(): DateTime
    {
        return new DateTime('now', new DateTimeZone('UTC'));
    }
}
