<?php

namespace SimpleSAML\Test\Module\genuniqueid\Auth\Process;

use PHPUnit\Framework\TestCase;

class GenerateUniqueIdTest extends TestCase
{
    /**
     * Helper function to run the filter with a given configuration.
     *
     * @param  array $config The filter configuration.
     * @param  array $request The request state.
     * @return array  The state array after processing.
     */
    private static function processFilter(array $config, array $request)
    {
        $filter = new \SimpleSAML\Module\genuniqueid\Auth\Process\GenerateUniqueId($config, null);
        $filter->process($request);
        return $request;
    }

    protected function setUp(): void
    {
        \SimpleSAML\Configuration::loadFromArray(['secretsalt' => 'test'], '[ARRAY]', 'simplesaml');
    }

    public function testNoConfig()
    {
        $request = [
            'Attributes' => [
                'objectGUID' => ['I5g7hZt5rUC610q9s7Tleg=='],
                'eduPersonPrincipalName' => ['example.org'],
            ],
        ];
        $result = self::processFilter([], $request);
        $this->assertEquals(
            [
                'Attributes' => [
                    'objectGUID' => ['I5g7hZt5rUC610q9s7Tleg=='],
                    'eduPersonPrincipalName' => ['example.org'],
                    'eduPersonUniqueId' => ['853b9823799b40adbad74abdb3b4e57a@example.org'],
                ],
            ],
            $result
        );
    }

    public function testScopeAttributeWithAt()
    {
        $request = [
            'Attributes' => [
                'objectGUID' => ['I5g7hZt5rUC610q9s7Tleg=='],
                'eduPersonPrincipalName' => ['nobody@example.org'],
            ],
        ];
        $result = self::processFilter([], $request);
        $this->assertEquals(
            [
                'Attributes' => [
                    'objectGUID' => ['I5g7hZt5rUC610q9s7Tleg=='],
                    'eduPersonPrincipalName' => ['nobody@example.org'],
                    'eduPersonUniqueId' => ['853b9823799b40adbad74abdb3b4e57a@example.org'],
                ],
            ],
            $result
        );
    }

    public function testDifferentAttributes()
    {
        $request = [
            'Attributes' => [
                'guid' => ['I5g7hZt5rUC610q9s7Tleg=='],
                'scope' => ['nobody@example.org'],
            ],
        ];
        $result = self::processFilter(
            [
                'sourceAttribute' => 'guid',
                'targetAttribute' => 'output',
                'scopeAttribute' => 'scope',
            ],
            $request
        );
        $this->assertEquals(
            [
                'Attributes' => [
                    'guid' => ['I5g7hZt5rUC610q9s7Tleg=='],
                    'scope' => ['nobody@example.org'],
                    'output' => ['853b9823799b40adbad74abdb3b4e57a@example.org'],
                ],
            ],
            $result
        );
    }

    public function testEmpty()
    {
        $request = [
            'Attributes' => [
                'eduPersonPrincipalName' => ['example.org'],
            ],
        ];
        $result = self::processFilter([], $request);
        $this->assertEquals(
            [
                'Attributes' => [
                    'eduPersonPrincipalName' => ['example.org'],
                ],
            ],
            $result
        );
    }

    public function testPrivacyHash()
    {
        $request = [
            'Attributes' => [
                'objectGUID' => ['I5g7hZt5rUC610q9s7Tleg=='],
                'eduPersonPrincipalName' => ['example.org'],
            ],
            'Source' => [
                'entityid' => 'https://localhost/idp',
            ],
        ];
        $result = self::processFilter(
            [
                'privacy' => true,
            ],
            $request
        );
        $this->assertEquals(
            [
                'objectGUID' => ['I5g7hZt5rUC610q9s7Tleg=='],
                'eduPersonPrincipalName' => ['example.org'],
                'eduPersonUniqueId' => ['81c1c9dd97912c8b9bc2ac502ab984d455694992e455d3bd6b98ad68696e04ff@example.org'],
            ],
            $result['Attributes']
        );
    }

    public function testPrivacyHashProxied()
    {
        $request = [
            'Attributes' => [
                'objectGUID' => ['I5g7hZt5rUC610q9s7Tleg=='],
                'eduPersonPrincipalName' => ['example.org'],
            ],
            'Source' => [
                'entityid' => 'https://localhost/proxy',
            ],
            'saml:sp:IdP' => 'https://localhost/idp',
        ];
        $result = self::processFilter(
            [
                'privacy' => true,
            ],
            $request
        );
        $this->assertEquals(
            [
                'objectGUID' => ['I5g7hZt5rUC610q9s7Tleg=='],
                'eduPersonPrincipalName' => ['example.org'],
                'eduPersonUniqueId' => ['81c1c9dd97912c8b9bc2ac502ab984d455694992e455d3bd6b98ad68696e04ff@example.org'],
            ],
            $result['Attributes']
        );
    }

    public function testUnknownFormat()
    {
        $request = [
            'Attributes' => [
                'objectGUID' => ['I5g7hZt5rUC610q9s7Tleg=='],
                'eduPersonPrincipalName' => ['nobody@example.org'],
            ],
        ];
        $this->expectException("SimpleSAML\Error\Exception");
        $this->expectExceptionMessage("attribute encoding");
        $result = self::processFilter(
            [
                'encoding' => 'unknown',
            ],
            $request
        );
    }

    public function testMicrosoft()
    {
        $request = [
            'Attributes' => [
                'objectGUID' => ['I5g7hZt5rUC610q9s7Tleg=='],
                'eduPersonPrincipalName' => ['nobody@example.org'],
            ],
        ];
        $result = self::processFilter(
            [
                'encoding' => 'microsoft',
            ],
            $request
        );
        $this->assertEquals(
            [
                'Attributes' => [
                    'objectGUID' => ['I5g7hZt5rUC610q9s7Tleg=='],
                    'eduPersonPrincipalName' => ['nobody@example.org'],
                    'eduPersonUniqueId' => ['853b9823799b40adbad74abdb3b4e57a@example.org'],
                ],
            ],
            $result
        );
    }

   public function testBogusMicrosoft()
    {
        $request = [
            'Attributes' => [
                'objectGUID' => ['=='],
                'eduPersonPrincipalName' => ['nobody@example.org'],
            ],
        ];
        $this->expectException("SimpleSAML\Error\Exception");
        $this->expectExceptionMessage("GenerateUniqueId: unable to unpack objectGUID");
        $result = self::processFilter(
            [
                'encoding' => 'microsoft',
            ],
            $request
        );
    }

    public function testEdirectory()
    {
        $request = [
            'Attributes' => [
                'guid' => ['gOH1SbeT2hGsbgAH6UDz7g=='],
                'eduPersonPrincipalName' => ['nobody@example.org'],
            ],
        ];
        $result = self::processFilter(
            [
                'encoding' => 'edirectory',
            ],
            $request
        );
        $this->assertEquals(
            [
                'Attributes' => [
                    'guid' => ['gOH1SbeT2hGsbgAH6UDz7g=='],
                    'eduPersonPrincipalName' => ['nobody@example.org'],
                    'eduPersonUniqueId' => ['80e1f549b793da11ac6e0007e940f3ee@example.org'],
                ],
            ],
            $result
        );
    }

    public function testBogusEdirectory()
    {
        $request = [
            'Attributes' => [
                'guid' => ['=='],
                'eduPersonPrincipalName' => ['nobody@example.org'],
            ],
        ];
        $this->expectException("SimpleSAML\Error\Exception");
        $this->expectExceptionMessage("GenerateUniqueId: unable to unpack guid");
        $result = self::processFilter(
            [
                'encoding' => 'edirectory',
            ],
            $request
        );
    }

    public function testOpenLdap()
    {
        $request = [
            'Attributes' => [
                'entryUUID' => ['914af8a6-d396-1038-966a-1f617ea1a993'],
                'eduPersonPrincipalName' => ['nobody@example.org'],
            ],
        ];
        $result = self::processFilter(
            [
                'encoding' => 'openldap',
            ],
            $request
        );
        $this->assertEquals(
            [
                'Attributes' => [
                    'entryUUID' => ['914af8a6-d396-1038-966a-1f617ea1a993'],
                    'eduPersonPrincipalName' => ['nobody@example.org'],
                    'eduPersonUniqueId' => ['914af8a6d3961038966a1f617ea1a993@example.org'],
                ],
            ],
            $result
        );
    }

    public function testBogusOpenLdap()
    {
        $request = [
            'Attributes' => [
                'entryUUID' => ['=='],
                'eduPersonPrincipalName' => ['nobody@example.org'],
            ],
        ];
        $this->expectException("SimpleSAML\Error\Exception");
        $this->expectExceptionMessage("GenerateUniqueId: unable to unpack entryUUID");
        $result = self::processFilter(
            [
                'encoding' => 'openldap',
            ],
            $request
        );
    }
}
