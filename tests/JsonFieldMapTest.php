<?php
namespace ParagonIE\CipherSweet\Tests;

use ParagonIE\CipherSweet\Constants;
use ParagonIE\CipherSweet\JsonFieldMap;
use PHPUnit\Framework\TestCase;

/**
 * @psalm-suppress
 */
class JsonFieldMapTest extends TestCase
{
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
