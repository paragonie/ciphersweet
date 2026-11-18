<?php
namespace ParagonIE\CipherSweet\Tests;

use ParagonIE\CipherSweet\Constants;
use ParagonIE\CipherSweet\Exception\CipherSweetException;
use ParagonIE\CipherSweet\Exception\JsonMapException;
use ParagonIE\CipherSweet\JsonFieldMap;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * @psalm-suppress
 */
class JsonFieldMapTest extends TestCase
{
    /**
     * @throws CipherSweetException
     */
    public function testScalarPathsForEachFieldType(): void
    {
        foreach ([
            'addBooleanField' => Constants::TYPE_BOOLEAN,
            'addFloatField' => Constants::TYPE_FLOAT,
            'addIntegerField' => Constants::TYPE_INT,
            'addTextField' => Constants::TYPE_TEXT
        ] as $method => $type) {
            foreach (['0', 0] as $path) {
                $map = new JsonFieldMap();
                $this->assertSame($map, $map->$method($path));
                $this->assertSame([[
                    'flat' => is_int($path) ? '#0000000000000000' : '$30',
                    'path' => [$path],
                    'type' => $type
                ]], $map->getMapping());
                $this->assertSame($map->toString(), (string) $map);
            }
        }
    }

    /**
     * @throws CipherSweetException
     * @throws JsonMapException
     */
    public function testScalarTemplateRoots(): void
    {
        $template = (new JsonFieldMap())->addFloatField('amount');
        foreach (['root', 2] as $root) {
            $map = new JsonFieldMap();
            $this->assertSame($map, $map->addMapFieldFromTemplate($root, $template));
            $this->assertSame([[
                'flat' => (is_int($root) ? '#0000000000000002' : '$726f6f74') . '.$616d6f756e74',
                'path' => [$root, 'amount'],
                'type' => Constants::TYPE_FLOAT
            ]], $map->getMapping());
        }
        $this->assertSame(['amount'], $template->getMapping()[0]['path']);
    }

    public static function invalidSerializedMaps(): array
    {
        $cases = [
            'invalid JSON' => ['{', 'Invalid JSON encoding'],
            'scalar JSON' => ['null', 'Invalid JSON encoding'],
            'missing fields' => ['{}', 'Invalid JSON: no fields key'],
            'integer field name' => ['{"fields":{"0":"string"}}', 'Invalid field'],
            'nonstring field type' => ['{"fields":{"$61":123}}', 'Invalid field'],
            'unknown path prefix' => ['{"fields":{"?61":"string"}}', 'Unknown path type: ?']
        ];
        foreach ($cases as &$case) {
            $case[0] = hash('crc32c', $case[0]) . $case[0];
        }
        unset($case);
        $cases['corrupted checksum'] = ['00000000{"fields":{}}', 'CRC32C invalid; was config corrupted?'];
        return $cases;
    }

    #[DataProvider('invalidSerializedMaps')]
    public function testRejectsInvalidSerializedMap(string $input, string $message): void
    {
        $this->expectException(CipherSweetException::class);
        $this->expectExceptionMessage($message);
        JsonFieldMap::fromString($input);
    }


    public function testArrayPathsForEachFieldType(): void
    {
        foreach ([
            'addBooleanField' => Constants::TYPE_BOOLEAN,
            'addFloatField' => Constants::TYPE_FLOAT,
            'addIntegerField' => Constants::TYPE_INT,
            'addTextField' => Constants::TYPE_TEXT
        ] as $method => $type) {
            $map = new JsonFieldMap();
            $this->assertSame($map, $map->$method(['nested', 1]));
            $this->assertSame([[
                'flat' => '$6e6573746564.#0000000000000001',
                'path' => ['nested', 1],
                'type' => $type
            ]], $map->getMapping());
        }
    }

    /**
     * @throws CipherSweetException
     * @throws JsonMapException
     */
    public function testFlatten()
    {
        $mapper = (new JsonFieldMap())
            ->addField(['foo', 'bar'], Constants::TYPE_TEXT)
            ->addField(['bar', 'baz'], Constants::TYPE_INT);

        $original = $mapper->toString();
        $mapped = $mapper->getMapping();
        $copy = $mapped;

        $this->assertCount(2, $mapped);

        $this->assertSame(['foo', 'bar'], $mapped[0]['path']);
        $this->assertSame(['bar', 'baz'], $mapped[1]['path']);

        $this->assertSame('$666f6f.$626172', $mapped[0]['flat']);
        $this->assertSame('$626172.$62617a', $mapped[1]['flat']);

        $this->assertSame(Constants::TYPE_TEXT, $mapped[0]['type']);
        $this->assertSame(Constants::TYPE_INT, $mapped[1]['type']);

        // Let's add a field:
        $mapper->addBooleanField(['foo', 0, 'bar', 123]);
        $mapped = $mapper->getMapping();

        $this->assertCount(3, $mapped);
        $this->assertSame(
            '$666f6f.#0000000000000000.$626172.#000000000000007b',
            $mapped[2]['flat']
        );
        $this->assertSame(['foo', 0, 'bar', 123], $mapped[2]['path']);
        $this->assertSame(Constants::TYPE_BOOLEAN, $mapped[2]['type']);

        $updated = $mapper->toString();
        $restored = JsonFieldMap::fromString($original);

        $old = $restored->getMapping();
        $this->assertCount(2, $old);
        $this->assertSame($old, $copy);

        $threeFields = JsonFieldMap::fromString($updated);
        $new = $threeFields->getMapping();
        $this->assertCount(3, $new);
        $this->assertSame($mapped, $new);
    }

    /**
     * @throws CipherSweetException
     * @throws JsonMapException
     */
    public function testTemplate()
    {
        $parent = new JsonFieldMap();
        $template = (new JsonFieldMap())
            ->addTextField(['foo', 'bar'])
            ->addIntegerField(['bar', 'baz']);
        $parent->addMapFieldFromTemplate(['data', 0], $template);
        $parent->addMapFieldFromTemplate(['data', 1], $template);

        $mapping = $parent->toString();
        $this->assertSame(
            '3be7ae2c{"fields":{' .
                '"$64617461.#0000000000000000.$666f6f.$626172":"string",' .
                '"$64617461.#0000000000000000.$626172.$62617a":"int",' .
                '"$64617461.#0000000000000001.$666f6f.$626172":"string",' .
                '"$64617461.#0000000000000001.$626172.$62617a":"int"' .
            '}}',
            $mapping
        );
    }
}
