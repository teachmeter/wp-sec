<?php

namespace App\Enums;

enum ComponentType: string
{
    case Core = 'core';
    case Plugin = 'plugin';
    case Theme = 'theme';
}
