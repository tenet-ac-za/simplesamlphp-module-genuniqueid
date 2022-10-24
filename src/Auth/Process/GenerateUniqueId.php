<?php

declare(strict_types=1);

namespace SimpleSAML\Module\genuniqueid\Auth\Process;

/**
 * Generate an eduPersonUniqueId attribute from various LDAP implementations' objectGUID
 *
 * @author    Guy Halse, http://orcid.org/0000-0002-9388-8592
 * @copyright Copyright (c) 2019, Tertiary Education and Research Network of South Africa
 * @package   SimpleSAMLphp
 */

class GenerateUniqueId extends \SimpleSAML\Auth\ProcessingFilter
{
    /** @var string $sourceAttribute The attribute we want to get a GUID from */
    private $sourceAttribute;

    /** @var string $targetAttribute The attribute we want to put a scoped unique Id into */
    private $targetAttribute = 'eduPersonUniqueId';

    /** @var string $scopeAttribute The attribute we extract the scope from. */
    private $scopeAttribute = 'eduPersonPrincipalName';

    /** @var string $encoding encoding of the GUID on the wire */
    private $encoding = 'microsoft';

    /** @var bool|false $privacy Whether to hash the resulting UUID to preserve privacy */
    private $privacy = false;

    /**
     * Initialize this filter, parse configuration.
     *
     * @param array $config Configuration information about this filter.
     * @param mixed $reserved For future use.
     * @throws \SimpleSAML\Error\Exception
     */
    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);
        assert(is_array($config));

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
                throw new \SimpleSAML\Error\Exception(
                    'GenerateUniqueId: attribute encoding "'.$this->encoding.'" is not known.'
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
     * @throws \SimpleSAML\Error\Exception
     */
    private function decodeActiveDirectory($value)
    {
        try {
            $decoded = base64_decode($value);
            $unpacked = unpack('Va/v2b/n2c/Nd', $decoded);
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
        } catch (\Exception $e) {
            throw new \SimpleSAML\Error\Exception(
                "GenerateUniqueId: unable to unpack ".$this->sourceAttribute.": ".$e->getMessage()
            );
        }
        return $guid;
    }

    /**
     * Decode big-endian binary encoding
     *
     * @param string $value base64 encoded value from LDAP
     * @return string decoded guid
     * @throws \SimpleSAML\Error\Exception
     */
    private function decodeBinaryBigEndian($value)
    {
        try {
            $decoded = base64_decode($value);
            $unpacked = unpack('Na/n2b/n2c/Nd', $decoded);
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
        } catch (\Exception $e) {
            throw new \SimpleSAML\Error\Exception(
                "GenerateUniqueId: unable to unpack ".$this->sourceAttribute.": ".$e->getMessage()
            );
        }
        return $guid;
    }

    /**
     * Decode textual UUID
     *
     * @param string $value value from LDAP
     * @return string decoded uuid
     * @throws \SimpleSAML\Error\Exception
     */
    private function decodeUuidString($value)
    {
        if (preg_match(
                '/^([0-9a-f]{8})\-?([0-9a-f]{4})\-?([0-9a-f]{4})\-?([0-9a-f]{4})\-?([0-9a-f]{12})$/',
                strtolower($value),
                $m
            )
        ) {
            return implode('', array_slice($m, 1, 5));
        } else {
            throw new \SimpleSAML\Error\Exception(
                "GenerateUniqueId: unable to unpack ".$this->sourceAttribute
            );
        }
    }

    /**
     * Generate a privacy-preserving hash
     *
     * @param string $value uuid
     * @param string $source authentication source
     * @return string hashed version
     * @throws \SimpleSAML\Error\Exception
     */
    private function privacyHash($value, $source = '')
    {
        return hash('sha256', $value.'|'.\SimpleSAML\Utils\Config::getSecretSalt().'|'.$source);
    }

    /**
     * Process this filter
     *
     * @param mixed &$request
     * @throws \SimpleSAML\Error\Exception
     * @return void
     */
    public function process(&$request): void
    {
        assert(is_array($request));
        assert(array_key_exists("Attributes", $request));

        if (!isset($request['Attributes'][$this->scopeAttribute])) {
            return;
        }
        if (!isset($request['Attributes'][$this->sourceAttribute])) {
            return;
        }
        if (!isset($request['Attributes'][$this->targetAttribute])) {
            $request['Attributes'][$this->targetAttribute] = [];
        }

        foreach ($request['Attributes'][$this->scopeAttribute] as $scope) {
            if (strpos($scope, '@') !== false) {
                $scope = explode('@', $scope, 2);
                $scope = $scope[1];
            }

            foreach ($request['Attributes'][$this->sourceAttribute] as $value) {

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
                        $uuid = preg_replace('/[^a-z0-9]/','', $value);
                }

                if ($uuid === null or $uuid === '') {
                    \SimpleSAML\Logger::warning(
                        'GenerateUniqueId: cowardly refusing to generate an empty unique id'
                    );
                    continue;
                }

                if ($this->privacy) {
                    assert(array_key_exists("Source", $request));
                    if (array_key_exists('saml:sp:IdP', $request)) {
                        $source = $request['saml:sp:IdP'];
                    } else {
                        $source = $request['Source']['entityid'];
                    }
                    $uuid = $this->privacyHash($uuid, $source);
                }

                $value = substr($uuid,0,64).'@'.$scope;
                if (in_array($value, $request['Attributes'][$this->targetAttribute], true)) {
                    // Already present
                    continue;
                }
                $request['Attributes'][$this->targetAttribute][] = $value;
            }
        }
    }
}
