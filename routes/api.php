<?php

use App\Http\Controllers\Api\VulnerabilityController;
use Illuminate\Support\Facades\Route;

Route::get('vulnerabilities/ticker', [VulnerabilityController::class, 'ticker'])->name('vulnerabilities.ticker');
Route::get('vulnerabilities', [VulnerabilityController::class, 'index'])->name('vulnerabilities.index');
Route::put('vulnerabilities/{vulnerability}/watch', [VulnerabilityController::class, 'watch'])->name('vulnerabilities.watch');
Route::delete('vulnerabilities/{vulnerability}/watch', [VulnerabilityController::class, 'unwatch'])->name('vulnerabilities.unwatch');
Route::patch('vulnerabilities/{vulnerability}', [VulnerabilityController::class, 'updateStatus'])->name('vulnerabilities.update-status');
