<?php

namespace Database\Factories;

use App\Enums\VulnerabilitySourceName;
use App\Models\SourceSync;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<SourceSync>
 */
class SourceSyncFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'source' => $this->faker->randomElement(VulnerabilitySourceName::cases()),
            'ran_at' => now(),
            'items_fetched' => $this->faker->numberBetween(0, 50),
            'items_new' => $this->faker->numberBetween(0, 10),
            'status' => 'success',
            'error' => null,
        ];
    }
}
