<?php

declare(strict_types=1);

namespace Mrjoops\CertificateStore;

use ValueError;

class CertificateStoreFactory
{
    /**
     * @throws ValueError
     */
    public static function createFromPKCS12(string $pkcs12, string $passphrase): CertificateStore
    {
        if (!openssl_pkcs12_read($pkcs12, $certs, $passphrase)) {
            throw new ValueError('Data is not a PKCS12 certificate store or passphrase is incorrect');
        }

        return new CertificateStore($certs['cert'], $certs['pkey'], $passphrase);
    }

    public static function createFromPKCS12File(string $filename, string $passphrase): CertificateStore
    {
        return self::createFromPKCS12(self::readFile($filename), $passphrase);
    }

    /**
     * @throws ValueError
     */
    protected static function readFile(string $filename): string
    {
        if (!is_file($filename)) {
            throw new ValueError("$filename is not a regular file");
        }

        $content = file_get_contents($filename);

        if (false === $content) {
            throw new ValueError("$filename is not readable");
        }

        return $content;
    }
}
