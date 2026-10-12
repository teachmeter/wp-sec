<?php

use App\Enums\ComponentType;
use App\Enums\SeverityLabel;
use App\Enums\VulnerabilitySourceName;
use App\Enums\VulnerabilityStatus;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('vulnerabilities', function (Blueprint $table): void {
            $table->id();
            $table->string('dedup_key')->unique();
            $table->enum('source', array_column(VulnerabilitySourceName::cases(), 'value'));
            $table->string('external_id');
            $table->string('cve_id')->nullable()->index();
            $table->string('title');
            $table->enum('component_type', array_column(ComponentType::cases(), 'value'));
            $table->string('component_slug')->nullable()->index();
            $table->string('component_name')->nullable();
            $table->enum('severity_label', array_column(SeverityLabel::cases(), 'value'))->default(SeverityLabel::None->value);
            $table->decimal('cvss_score', 3, 1)->nullable();
            $table->string('cvss_vector')->nullable();
            $table->boolean('is_kev_exploited')->default(false);
            $table->string('patched_version')->nullable();
            $table->text('description')->nullable();
            $table->string('reference_url')->nullable();
            $table->string('source_url')->nullable();
            $table->timestamp('published_at')->nullable();
            $table->timestamp('first_seen_at');
            $table->timestamp('last_seen_at');
            $table->enum('status', array_column(VulnerabilityStatus::cases(), 'value'))->default(VulnerabilityStatus::New->value);
            $table->boolean('affects_our_stack')->default(false);
            $table->timestamps();

            $table->index(['severity_label', 'published_at']);
            $table->index(['is_kev_exploited', 'published_at']);
            $table->index(['affects_our_stack', 'published_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('vulnerabilities');
    }
};
