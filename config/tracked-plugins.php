<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Tracked Plugin Slugs
    |--------------------------------------------------------------------------
    |
    | The WordPress.org plugin/theme slugs your company actually runs. Any
    | vulnerability matching one of these slugs is flagged "affects_our_stack"
    | so the dashboard can separate it from general WordPress ecosystem noise.
    | WordPress core itself always affects your stack.
    |
    | Override with a comma-separated TRACKED_PLUGIN_SLUGS env value, or edit
    | the array below directly.
    |
    */

    'slugs' => array_filter(array_map(
        'trim',
        explode(',', env('TRACKED_PLUGIN_SLUGS', implode(',', [
            // 'contact-form-7',
            // 'yoast-seo',
            // 'woocommerce',
        ])))
    )),

];
