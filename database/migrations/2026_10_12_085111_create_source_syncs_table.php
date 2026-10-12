<?php

use App\Enums\VulnerabilitySourceName;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('source_syncs', function (Blueprint $table): void {
            $table->id();
            $table->enum('source', array_column(VulnerabilitySourceName::cases(), 'value'));
            $table->timestamp('ran_at');
            $table->unsignedInteger('items_fetched')->default(0);
            $table->unsignedInteger('items_new')->default(0);
            $table->string('status');
            $table->text('error')->nullable();
            $table->timestamps();

            $table->index(['source', 'ran_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('source_syncs');
    }
};
