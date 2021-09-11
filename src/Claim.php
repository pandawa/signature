<?php

declare(strict_types=1);

namespace Pandawa\Signature;

use DateTime;

/**
 * @author  Iqbal Maulana <iq.bluejack@gmail.com>
 */
class Claim
{
    protected string $requestId;
    protected string $targetPath;
    protected ?string $body;
    protected DateTime $requestDate;

    public function __construct(string $requestId, string $targetPath, DateTime $requestDate, ?string $body = null)
    {
        $this->requestId = $requestId;
        $this->targetPath = $targetPath;
        $this->body = $body;
        $this->requestDate = $requestDate;
    }

    public function getRequestId(): string
    {
        return $this->requestId;
    }

    public function getTargetPath(): string
    {
        return $this->targetPath;
    }

    public function getBody(): ?string
    {
        return $this->body;
    }

    public function getRequestDate(): DateTime
    {
        return $this->requestDate;
    }

    public function getRequestDateString(): string
    {
        $date = $this->requestDate->format('c');

        return substr($date, 0, strpos($date, '+')) . 'Z';
    }

    public function getDigest(): ?string
    {
        if (null === $this->getBody()) {
            return null;
        }

        return base64_encode(hash('sha256', $this->getBody(), true));
    }

    public function toArray(): array
    {
        return array_filter([
            $this->getRequestId(),
            $this->getRequestDateString(),
            $this->getTargetPath(),
            $this->getDigest(),
        ]);
    }
}
