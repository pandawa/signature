<?php

declare(strict_types=1);

namespace Pandawa\Signature\Contract;

/**
 * @author  Iqbal Maulana <iq.bluejack@gmail.com>
 */
interface ClientRepositoryInterface
{
    public function findByClientId(string $clientId): ?ClientInterface;
}
