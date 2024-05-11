<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet;

use ParagonIE\ConstantTime\Binary;

/**
 * Defines an interface for combining multiple plaintext fields into the AAD
 * for a given field.
 */
class AAD
{
    public function __construct(
        protected array $fieldNames = [],
        protected array $literals = [],
        protected bool $legacy = false
    ) {}

    public function addFieldName(string $fieldName): self
    {
        if (!in_array($fieldName, $this->fieldNames, true)) {
            $this->fieldNames [] = $fieldName;
        }
        return $this;
    }

    public function addLiteral(string $literal): self
    {
        if (!in_array($literal, $this->literals, true)) {
            $this->literals [] = $literal;
        }
        return $this;
    }

    /**
     * Returns a canonicalized string representing these AAD inputs
     *
     * @param array $plaintextRow
     * @return string
     */
    public function canonicalize(array $plaintextRow = []): string
    {
        if ($this->legacy) {
            if (count($this->fieldNames) === 0 && count($this->literals) === 0) {
                return '';
            }
            // Old behavior, only one value, so we just return that:
            if (count($this->fieldNames) === 1) {
                $fieldName = array_values($this->fieldNames)[0];
                return (string) $plaintextRow[$fieldName];
            } elseif (count($this->literals) === 1) {
                return (string) array_values($this->literals)[0];
            }
        }
        // We assume field names and literal AAD values are not sensitive
        // and can therefore be sorted without worry of side-channel leaks
        sort($this->fieldNames);
        sort($this->literals);

        $encoded = '';
        // First 8 bytes: number of pieces total
        $count = count($this->fieldNames) + count($this->literals);
        $encoded .= self::le64($count);

        // Next 8 bytes: number of fields
        $count = count($this->fieldNames);
        $encoded .= self::le64($count);

        // Next 8 bytes: number of literals
        $count = count($this->literals);
        $encoded .= self::le64($count);

        // Now let's encode each field
        // |name| + name + |value| + value
        foreach ($this->fieldNames as $fieldName) {
            $encoded .= self::le64(Binary::safeStrlen($fieldName));
            $encoded .= $fieldName;

            $fieldValue = (string) ($plaintextRow[$fieldName] ?? '');
            $encoded .= self::le64(Binary::safeStrlen($fieldValue));
            $encoded .= $fieldValue;
        }

        // Now encode each literal value
        // |value| + value
        foreach ($this->literals as $literal) {
            $literalValue = (string) $literal;
            $encoded .= self::le64(Binary::safeStrlen($literalValue));
            $encoded .= $literalValue;
        }

        // We should now have a canonical string representing this AAD
        return $encoded;
    }

    /**
     * Return a new AAD object with all field values collapsed to literals.
     *
     * @param array $row
     * @return self
     */
    public function getCollapsed(array $row): self
    {
        $clone = new AAD([], $this->literals);
        sort($this->fieldNames);
        foreach ($this->fieldNames as $fieldName) {
            if (array_key_exists($fieldName, $row)) {
                $clone->addLiteral((string) $row[$fieldName]);
            }
        }
        sort($clone->literals);
        return $clone;
    }

    public function getFieldNames(): array
    {
        return $this->fieldNames;
    }

    public function getLiterals(): array
    {
        return $this->literals;
    }

    /**
     * Append multiple AADs to the same field
     *
     * @param AAD $other
     * @return $this
     */
    public function merge(AAD $other): self
    {
        $self = clone $this;
        foreach ($other->fieldNames as $fieldName) {
            if (!in_array($fieldName, $self->fieldNames, true)) {
                $self->fieldNames []= $fieldName;
            }
        }
        foreach ($other->literals as $literal) {
            if (!in_array($literal, $self->literals, true)) {
                $self->literals []= $literal;
            }
        }
        // We aren't using legacy mode for this:
        $self->legacy = false;
        return $self;
    }

    /**
     * Enforce for a field name. Enforces legacy behavior.
     *
     * @param string|AAD $input
     * @return self
     */
    public static function field(string|AAD $input): self
    {
        if ($input instanceof AAD) {
            return clone $input;
        } elseif (empty($input)) {
            return new AAD([], [], true);
        }
        return new AAD([$input], [], true);
    }

    /**
     * Initialize for a string literal. Enforces legacy behavior.
     *
     * @param string|AAD $input
     * @return self
     */
    public static function literal(string|AAD $input): self
    {
        if ($input instanceof AAD) {
            return clone $input;
        } elseif (empty($input)) {
            return new AAD([], [], true);
        }
        return new AAD([], [$input], true);
    }

    private static function le64(int $length): string
    {
        return pack('P', $length);
    }
}
