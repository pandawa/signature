<?php

declare(strict_types=1);

namespace Pandawa\Signature;

use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Container\Container;
use Pandawa\Component\Foundation\Bundle\Bundle;

/**
 * @author  Iqbal Maulana <iq.bluejack@gmail.com>
 */
class SignatureBundle extends Bundle
{
    public function boot(): void
    {
        $this->auth()->extend('signature', function (Container $app, string $name, array $config) {
            return new SignatureGuard(
                $app->get($config['repository']),
                $app->get('request'),
                $config['ttl'] ?? null,
                $config['algo'] ?? 'sha256'
            );
        });
    }

    protected function auth(): AuthManager
    {
        return $this->app['auth'];
    }
}
