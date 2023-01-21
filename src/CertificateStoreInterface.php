<?php

declare(strict_types=1);

namespace Mrjoops\CertificateStore;

interface CertificateStoreInterface
{
    public function getPassphrase(): string;

    public function hasPassphrase(): bool;

    public function toPEM(string $outputPath = '', string $filename = ''): string;
}
