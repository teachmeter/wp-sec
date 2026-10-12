<?php

namespace App\Vulnerabilities;

use App\Enums\SeverityLabel;

class SeverityNormalizer
{
    /**
     * Normalize a source's raw CVSS score and/or severity rating into our enum + float score.
     * Sources disagree on key names and casing for the rating, and some omit the score entirely,
     * so the score (when present) always wins and the rating string is only a fallback.
     *
     * @return array{0: SeverityLabel, 1: ?float}
     */
    public static function fromScoreAndRating(int|float|string|null $score, ?string $rating): array
    {
        $normalizedScore = is_numeric($score) ? round((float) $score, 1) : null;

        if ($normalizedScore !== null) {
            return [self::fromScore($normalizedScore), $normalizedScore];
        }

        return [self::fromRating($rating), null];
    }

    public static function fromScore(float $score): SeverityLabel
    {
        return match (true) {
            $score >= 9.0 => SeverityLabel::Critical,
            $score >= 7.0 => SeverityLabel::High,
            $score >= 4.0 => SeverityLabel::Medium,
            $score > 0.0 => SeverityLabel::Low,
            default => SeverityLabel::None,
        };
    }

    public static function fromRating(?string $rating): SeverityLabel
    {
        return match (strtolower((string) $rating)) {
            'critical' => SeverityLabel::Critical,
            'high', 'h' => SeverityLabel::High,
            'medium', 'moderate', 'm' => SeverityLabel::Medium,
            'low', 'l' => SeverityLabel::Low,
            default => SeverityLabel::None,
        };
    }
}
