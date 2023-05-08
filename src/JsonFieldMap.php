<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet;

use ParagonIE\CipherSweet\Exception\{
    CipherSweetException,
    JsonMapException
};
use ParagonIE\ConstantTime\{
    Binary,
    Hex
};

class JsonFieldMap
{
    /** @var array<string, string> */
    private array $fields = [];

    /**
     * @param string $string
     * @return static
     *
     * @throws CipherSweetException
     */
    public static function fromString(string $string): static
    {
        $crc32 = Binary::safeSubstr($string, 0, 8);
        $json = Binary::safeSubstr($string, 8);
        $calc = hash('crc32c', $json);
        if (!Util::hashEquals($calc, $crc32)) {
            throw new CipherSweetException("CRC32C invalid; was config corrupted?");
        }

        $decoded = \json_decode($json, true);
        if (!\is_array($decoded)) {
            throw new CipherSweetException("Invalid JSON encoding");
        }
        if (!\array_key_exists('fields', $decoded)) {
            throw new CipherSweetException("Invalid JSON: no fields key");
        }

        /** @psalm-suppress UnsafeInstantiation */
        $self = new static();

        // Let's validate the input:
        foreach ($decoded['fields'] as $flat => $type) {
            if (!\is_string($flat) || !\is_string($type)) {
                throw new CipherSweetException("Invalid field");
            }

            // This will throw if an invalid path is provided:
            $self->unflattenPath($flat);
        }

        // If we're still here, we're golden
        $self->fields = $decoded['fields'];
        return $self;
    }

    /**
     * @param array<array-key, string|int>|int|string $indices
     * @return static
     *
     * @throws JsonMapException
     */
    public function addBooleanField(array|int|string $indices): static
    {
        if (\is_string($indices) || \is_int($indices)) {
            $indices = [$indices];
        }
        return $this->addField($indices, Constants::TYPE_BOOLEAN);
    }

    /**
     * @param array<array-key, string|int>|int|string $indices
     * @return static
     *
     * @throws JsonMapException
     */
    public function addFloatField(array|int|string $indices): static
    {
        if (\is_string($indices) || \is_int($indices)) {
            $indices = [$indices];
        }
        return $this->addField($indices, Constants::TYPE_FLOAT);
    }

    /**
     * @param array<array-key, string|int>|int|string $indices
     * @return static
     *
     * @throws JsonMapException
     */
    public function addIntegerField(array|int|string $indices): static
    {
        if (\is_string($indices) || \is_int($indices)) {
            $indices = [$indices];
        }
        return $this->addField($indices, Constants::TYPE_INT);
    }

    /**
     * @param array<array-key, string|int>|int|string $indices
     * @return static
     *
     * @throws JsonMapException
     */
    public function addTextField(array|int|string $indices): static
    {
        if (\is_string($indices) || \is_int($indices)) {
            $indices = [$indices];
        }
        return $this->addField($indices, Constants::TYPE_TEXT);
    }

    /**
     * @param array<array-key, string|int> $indices
     * @param string $type
     * @return static
     *
     * @throws JsonMapException
     */
    public function addField(array $indices, string $type): static
    {
        $path = $this->flattenPath($indices);
        $this->fields[$path] = $type;
        return $this;
    }

    /**
     * Adds an object's configuration
     *
     * @param array|int|string $rootIndices
     * @param JsonFieldMap $template
     * @return static
     *
     * @throws CipherSweetException
     */
    public function addMapFieldFromTemplate(
        array|int|string $rootIndices,
        JsonFieldMap $template
    ): static {
        if (\is_string($rootIndices) || \is_int($rootIndices)) {
            $rootIndices = [$rootIndices];
        }

        foreach ($template->getMapping() as $mapping) {
            $indices = [...$rootIndices, ...$mapping['path']];
            $this->addField($indices, $mapping['type']);
        }
        return $this;
    }

    /**
     * @param array<array-key, string|int> $indices
     * @return string
     *
     * @throws JsonMapException
     */
    protected function flattenPath(array $indices): string
    {
        $pieces = [];
        foreach ($indices as $index) {
            if (\is_int($index)) {
                $pieces []= '#' . Hex::encode(pack('J', $index));
            } elseif (\is_string($index)) {
                $pieces []= '$' . Hex::encode($index);
            } else {
                throw new JsonMapException('Invalid type');
            }
        }
        return implode('.', $pieces);
    }

    /**
     * @throws CipherSweetException
     */
    protected function unflattenPath(string $flattened): array
    {
        $pieces = \explode('.', $flattened);
        $path = [];
        foreach ($pieces as $piece) {
            $decoded = Hex::decode(Binary::safeSubstr($piece, 1));
            if ($piece[0] === '#') {
                $unpack = \unpack('J', $decoded);
                $path[] = (int) $unpack[1];
            } elseif ($piece[0] === '$') {
                $path[] = $decoded;
            } else {
                throw new CipherSweetException("Unknown path type: {$piece[0]}");
            }
        }
        return $path;
    }

    /**
     * @return array<array{flat:string,path:array,type:string}>
     *
     * @throws CipherSweetException
     */
    public function getMapping(): array
    {
        $mapping = [];
        foreach ($this->fields as $field => $type) {
            $mapping []= [
                'flat' => $field,
                'path' => $this->unflattenPath($field),
                'type' => $type
            ];
        }
        return $mapping;
    }

    /**
     * @return string
     */
    public function toString(): string
    {
        $json = \json_encode(['fields' => $this->fields]);
        $crc = \hash('crc32c', $json);
        return $crc . $json;
    }

    public function __toString()
    {
        return $this->toString();
    }
}
