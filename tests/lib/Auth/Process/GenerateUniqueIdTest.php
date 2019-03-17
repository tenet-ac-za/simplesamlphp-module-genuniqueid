<?php

namespace SimpleSAML\Test\Module\genuniqueid\Auth\Process;

class GenerateUniqueIdTest extends \PHPUnit_Framework_TestCase
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

    protected function setUp()
    {
        \SimpleSAML\Configuration::loadFromArray([], '[ARRAY]', 'simplesaml');
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
}
