<?php

declare(strict_types=1);

namespace Mrjoops\CertificateStore;

use Exception;
use InvalidArgumentException;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;

class CertificateStore implements CertificateStoreInterface
{
    protected OpenSSLCertificate $certificate;
    protected string $passphrase;
    protected OpenSSLAsymmetricKey $privateKey;

    public function __construct(string $certificate, string $privateKey, string $passphrase = '')
    {
        $this->setCertificate($certificate);
        $this->setPrivateKey($privateKey, $passphrase);
    }

    public function getCertificate(): string
    {
        if (!openssl_x509_export($this->certificate, $out)) {
            throw new Exception('Certificate cannot be exported');
        }

        return $out;
    }

    public function getPassphrase(): string
    {
        return $this->passphrase;
    }

    /**
     * @throws Exception
     */
    public function getPrivateKey(): string
    {
        if (empty($this->passphrase)) {
            $exportOk = openssl_pkey_export($this->privateKey, $out);
        } else {
            $exportOk = openssl_pkey_export($this->privateKey, $out, $this->passphrase);
        }

        if (!$exportOk) {
            throw new Exception('Private key cannot be exported');
        }

        return $out;
    }

    public function hasPassphrase(): bool
    {
        return 0 !== strlen($this->passphrase);
    }

    /**
     * @throws InvalidArgumentException
     */
    public function setCertificate(string $data): self
    {
        $x509 = openssl_x509_read($data);

        if (false === $x509) {
            throw new InvalidArgumentException('Data does not contain a valid certificate');
        }

        $this->certificate = $x509;

        return $this;
    }

    /**
     * @throws InvalidArgumentException
     */
    public function setPrivateKey(string $privateKey, string $passphrase = ''): self
    {
        if (empty($passphrase)) {
            $pkey = openssl_pkey_get_private($privateKey);
        } else {
            $pkey = openssl_pkey_get_private($privateKey, $passphrase);
        }

        if (false === $pkey) {
            throw new InvalidArgumentException('Data  does not contain a valid private key or passphrase is incorrect');
        }

        $this->passphrase = $passphrase;
        $this->privateKey = $pkey;

        return $this;
    }

    /**
     * @throws Exception
     */
    public function toPEM(string $outputPath = '', string $filename = ''): string
    {
        if (empty($outputPath)) {
            $outputPath = sys_get_temp_dir();
        }

        if (empty($filename)) {
            $details = openssl_x509_parse($this->certificate);
            $filename = $outputPath . '/' . hash('sha256', $details['name']) . '.pem';
        }

        if (false === file_put_contents($filename, $this->getPrivateKey() . $this->getCertificate())) {
            throw new Exception("$filename is not writable");
        }

        return $filename;
    }
}
