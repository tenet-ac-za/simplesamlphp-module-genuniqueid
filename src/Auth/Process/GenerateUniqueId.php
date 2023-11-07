<?php

declare(strict_types=1);

namespace SimpleSAML\Module\genuniqueid\Auth\Process;

use SimpleSAML\Assert\Assert;
use SimpleSAML\Auth;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Utils;

/**
 * Generate an eduPersonUniqueId attribute from various LDAP implementations' objectGUID
 *
 * @author    Guy Halse, http://orcid.org/0000-0002-9388-8592
 * @copyright Copyright (c) 2019, Tertiary Education and Research Network of South Africa
 * @package   SimpleSAMLphp
 */

class GenerateUniqueId extends Auth\ProcessingFilter
{
    /** @var string $sourceAttribute The attribute we want to get a GUID from */
    private string $sourceAttribute;

    /** @var string $targetAttribute The attribute we want to put a scoped unique Id into */
    private string $targetAttribute = 'eduPersonUniqueId';

    /** @var string $scopeAttribute The attribute we extract the scope from. */
    private string $scopeAttribute = 'eduPersonPrincipalName';

    /** @var string $encoding encoding of the GUID on the wire */
    private string $encoding = 'microsoft';

    /** @var bool|false $privacy Whether to hash the resulting UUID to preserve privacy */
    private bool $privacy = false;

    /**
     * Initialize this filter, parse configuration.
     *
     * @param array $config Configuration information about this filter.
     * @param mixed $reserved For future use.
     * @throws \SimpleSAML\Error\Exception
     */
    public function __construct(array $config, $reserved)
    {
        parent::__construct($config, $reserved);

        if (array_key_exists('targetAttribute', $config)) {
            $this->targetAttribute = (string)$config['targetAttribute'];
        }
        if (array_key_exists('scopeAttribute', $config)) {
            $this->scopeAttribute = (string)$config['scopeAttribute'];
        }
        if (array_key_exists('privacy', $config)) {
            $this->privacy = (bool)$config['privacy'];
        }
        if (array_key_exists('encoding', $config)) {
            $this->encoding = strtolower((string)$config['encoding']);
        }

        /* set the default source attribute based on encoding */
        switch ($this->encoding) {
            case 'microsoft':
            case 'activedirectory':
                $this->sourceAttribute = 'objectGUID';
                break;
            case 'edirectory':
                $this->sourceAttribute = 'guid';
                break;
            case 'openldap':
                $this->sourceAttribute = 'entryUUID';
                break;
            default:
                throw new Error\Exception(
                    'GenerateUniqueId: attribute encoding "' . $this->encoding . '" is not known.'
                );
        }
        /* now allow it to be overridden in config */
        if (array_key_exists('sourceAttribute', $config)) {
            $this->sourceAttribute = (string)$config['sourceAttribute'];
        }
    }

    /**
     * Decode Microsoft's mixed-endian binary encoding
     * http://php.net/manual/en/function.mssql-guid-string.php#119391
     *
     * @param string $value base64 encoded value from LDAP
     * @return string decoded guid
     * @throws \SimpleSAML\Assert\AssertionFailedException
     */
    private function decodeActiveDirectory(string $value): string
    {
        $decoded = base64_decode($value);
        Assert::notFalse($decoded, 'unable to unpack ' . $this->sourceAttribute . ': base64_decode failed');
        Assert::minLength($decoded, 12, 'unable to unpack ' . $this->sourceAttribute . ': decoded string too short');
        $unpacked = unpack('Va/v2b/n2c/Nd', $decoded);
        Assert::notFalse($unpacked, 'unable to unpack ' . $this->sourceAttribute . ': unpack failed');
        $guid = strtolower(
            sprintf(
                '%08X%04X%04X%04X%04X%08X',
                $unpacked['a'],
                $unpacked['b1'],
                $unpacked['b2'],
                $unpacked['c1'],
                $unpacked['c2'],
                $unpacked['d']
            )
        );
        Assert::length($guid, 32, 'unable to unpack ' . $this->sourceAttribute . ': repack failed');
        return $guid;
    }

    /**
     * Decode big-endian binary encoding
     *
     * @param string $value base64 encoded value from LDAP
     * @return string decoded guid
     * @throws \SimpleSAML\Assert\AssertionFailedException
     */
    private function decodeBinaryBigEndian(string $value): string
    {
        $decoded = base64_decode($value, true);
        Assert::notFalse($decoded, 'unable to unpack ' . $this->sourceAttribute . ': base64_decode failed');
        Assert::minLength($decoded, 12, 'unable to unpack ' . $this->sourceAttribute . ': decoded string too short');
        $unpacked = unpack('Na/n2b/n2c/Nd', $decoded);
        Assert::notFalse($unpacked, 'unable to unpack ' . $this->sourceAttribute . ': unpack failed');
        $guid = strtolower(
            sprintf(
                '%08X%04X%04X%04X%04X%08X',
                $unpacked['a'],
                $unpacked['b1'],
                $unpacked['b2'],
                $unpacked['c1'],
                $unpacked['c2'],
                $unpacked['d']
            )
        );
        Assert::length($guid, 32, 'unable to unpack ' . $this->sourceAttribute . ': repack failed');
        return $guid;
    }

    /**
     * Decode textual UUID
     *
     * @param string $value value from LDAP
     * @return string decoded uuid
     * @throws \SimpleSAML\Assert\AssertionFailedException
     */
    private function decodeUuidString(string $value): string
    {
        preg_match(
            '/^([0-9a-f]{8})\-?([0-9a-f]{4})\-?([0-9a-f]{4})\-?([0-9a-f]{4})\-?([0-9a-f]{12})$/',
            strtolower($value),
            $m
        );
        Assert::count($m, 6, 'unable to unpack ' . $this->sourceAttribute . ': wrong number of parts in uuid');

        $guid = implode('', array_slice($m, 1, 5));
        Assert::length($guid, 32, 'unable to unpack ' . $this->sourceAttribute . ': repack failed');
        return $guid;
    }

    /**
     * Generate a privacy-preserving hash
     *
     * @param string $value uuid
     * @param string $source authentication source
     * @return string hashed version
     */
    private function privacyHash(string $value, string $source = ''): string
    {
        $salter = new Utils\Config();
        return hash('sha256', $value . '|' . $salter->getSecretSalt() . '|' . $source);
    }

    /**
     * Process this filter
     *
     * @param mixed &$state
     * @throws \SimpleSAML\Assert\AssertionFailedException
     * @return void
     */
    public function process(array &$state): void
    {
        Assert::keyExists($state, "Attributes");

        if (!isset($state['Attributes'][$this->scopeAttribute])) {
            return;
        }
        if (!isset($state['Attributes'][$this->sourceAttribute])) {
            return;
        }
        if (!isset($state['Attributes'][$this->targetAttribute])) {
            $state['Attributes'][$this->targetAttribute] = [];
        }

        foreach ($state['Attributes'][$this->scopeAttribute] as $scope) {
            if (strpos($scope, '@') !== false) {
                $scopeParts = explode('@', $scope, 2);
                /** @psalm-suppress PossiblyUndefinedArrayOffset */
                $scope = $scopeParts[1];
            }

            foreach ($state['Attributes'][$this->sourceAttribute] as $value) {
                switch ($this->encoding) {
                    case 'microsoft':
                    case 'activedirectory':
                        $uuid = $this->decodeActiveDirectory($value);
                        break;
                    case 'edirectory':
                        $uuid = $this->decodeBinaryBigEndian($value);
                        break;
                    case 'openldap':
                        $uuid = $this->decodeUuidString($value);
                        break;
                    default:
                        $uuid = preg_replace('/[^a-z0-9]/', '', (string) $value);
                }

                if ($uuid === null or $uuid === '') {
                    Logger::warning(
                        'GenerateUniqueId: cowardly refusing to generate an empty unique id'
                    );
                    continue;
                }

                if ($this->privacy) {
                    Assert::keyExists($state, "Source");
                    if (array_key_exists('saml:sp:IdP', $state)) {
                        $source = $state['saml:sp:IdP'];
                    } else {
                        $source = $state['Source']['entityid'];
                    }
                    $uuid = $this->privacyHash($uuid, $source);
                }

                $value = substr($uuid, 0, 64) . '@' . $scope;
                if (in_array($value, $state['Attributes'][$this->targetAttribute], true)) {
                    // Already present
                    continue;
                }
                $state['Attributes'][$this->targetAttribute][] = $value;
            }
        }
    }
}
