<?php

declare(strict_types=1);

namespace Mrjoops\CertificateStore;

interface CertificateStoreInterface
{
    /**
     * @return string
     */
    public function getPassphrase(): string;

    /**
     * @return bool
     */
    public function hasPassphrase(): bool;

    /**
     * @param string $filename
     *
     * @return string Output path
     * @return string File name
     */
    public function toPEM(string $path = '', string $filename = ''): string;
}
