<?php

declare(strict_types=1);

namespace Pandawa\Signature\Contract;

/**
 * @author  Iqbal Maulana <iq.bluejack@gmail.com>
 */
interface Client
{
    public function getId(): string;

    public function getSecret(): string;
}
