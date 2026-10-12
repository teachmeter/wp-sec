<?php

namespace App\Models;

use App\Enums\VulnerabilitySourceName;
use Database\Factories\SourceSyncFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class SourceSync extends Model
{
    /** @use HasFactory<SourceSyncFactory> */
    use HasFactory;

    /**
     * @var array<int, string>
     */
    protected $fillable = [
        'source',
        'ran_at',
        'items_fetched',
        'items_new',
        'status',
        'error',
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'source' => VulnerabilitySourceName::class,
            'ran_at' => 'datetime',
        ];
    }
}
