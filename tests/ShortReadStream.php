<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\Tests;

/**
 * Used for unit testing only.
 */
class ShortReadStream
{
    public $context;
    public static string $data = '';
    public static int $headerLength = 0;
    private int $position = 0;

    public function stream_open($path, $mode, $options, &$openedPath): bool
    {
        $this->position = 0;
        return true;
    }

    public function stream_read($count): string
    {
        $limit = $this->position < self::$headerLength
            ? self::$headerLength - $this->position
            : 7;
        $data = substr(self::$data, $this->position, min($count, $limit));
        $this->position += strlen($data);
        return $data;
    }

    public function stream_eof(): bool
    {
        return $this->position >= strlen(self::$data);
    }

    public function stream_tell(): int
    {
        return $this->position;
    }

    public function stream_seek($offset, $whence): bool
    {
        $position = match ($whence) {
            SEEK_SET => $offset,
            SEEK_CUR => $this->position + $offset,
            SEEK_END => strlen(self::$data) + $offset,
        };
        if ($position < 0) {
            return false;
        }
        $this->position = $position;
        return true;
    }

    public function stream_stat(): array
    {
        return ['size' => strlen(self::$data)];
    }
}
