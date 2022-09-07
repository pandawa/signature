<?php

declare(strict_types=1);

namespace Pandawa\Signature\Contract;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * @author  Iqbal Maulana <iq.bluejack@gmail.com>
 */
interface ClientInterface extends Authenticatable
{
    public function getId(): string;

    public function getSecret(): string;
}
