<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('vulnerabilities', function (Blueprint $table): void {
            $table->timestamp('watched_at')->nullable()->index();
        });
    }

    public function down(): void
    {
        Schema::table('vulnerabilities', function (Blueprint $table): void {
            $table->dropIndex(['watched_at']);
            $table->dropColumn('watched_at');
        });
    }
};
