<?php
declare(strict_types=1);
namespace ParagonIE\CipherSweet\Tests\TestEnums;

enum TestUnitEnum
{
    case Invalid;
    case Open;
    case Resolved;
    case Pending;
}
