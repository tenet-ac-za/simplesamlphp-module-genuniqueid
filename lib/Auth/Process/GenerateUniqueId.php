<?php

namespace SimpleSAML\Module\genuniqueid\Auth\Process;

/**
 * Generate an eduPersonUniqueId attribute from various LDAP implementations' objectGUID
 *
 * @author    Guy Halse, http://orcid.org/0000-0002-9388-8592
 * @copyright Copyright (c) 2019, SAFIRE - South African Identity Federation
 * @package   SimpleSAMLphp
 */

class GenerateUniqueId extends \SimpleSAML\Auth\ProcessingFilter
{
    /** @var string $sourceAttribute The attribute we want to get a binary GUID from */
    private $sourceAttribute = 'objectGUID';

    /** @var string $targetAttribute The attribute we want to put a scoped unique Id into */
    private $targetAttribute = 'eduPersonUniqueId';

    /** @var string $scopeAttribute The attribute we extract the scope from. */
    private $scopeAttribute = 'eduPersonPrincipalName';

    /**
     * Initialize this filter, parse configuration.
     *
     * @param array $config Configuration information about this filter.
     * @param mixed $reserved For future use.
     */
    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);
        assert('is_array($config)');

        if (array_key_exists('sourceAttribute', $config)) {
            $this->sourceAttribute = (string)$config['sourceAttribute'];
        }
        if (array_key_exists('targetAttribute', $config)) {
            $this->targetAttribute = (string)$config['targetAttribute'];
        }
        if (array_key_exists('scopeAttribute', $config)) {
            $this->scopeAttribute = (string)$config['scopeAttribute'];
        }
    }

    /**
     * Process this filter
     *
     * @param mixed &$request
     * @throws \SimpleSAML\Error\Exception
     */
    public function process(&$request)
    {
        assert('is_array($request)');
        assert('array_key_exists("Attributes", $request)');

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
                        "GenerateEduPersonUniqueId: unable to unpack ".$this->sourceAttribute.": ".$e->getMessage()
                    );
                }
                $value = $guid.'@'.$scope;
                if (in_array($value, $request['Attributes'][$this->targetAttribute], true)) {
                    // Already present
                    continue;
                }
                $request['Attributes'][$this->targetAttribute][] = $value;
            }
        }
    }
}
