<?php

namespace App\Enums;

enum SeverityLabel: string
{
    case None = 'none';
    case Low = 'low';
    case Medium = 'medium';
    case High = 'high';
    case Critical = 'critical';

    public function isHighRisk(): bool
    {
        return match ($this) {
            self::High, self::Critical => true,
            default => false,
        };
    }
}
