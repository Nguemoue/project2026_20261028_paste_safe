<?php

declare(strict_types=1);

/**
 * Write a fake log to stdout so you can try paste-safe without real secrets.
 *
 *   php examples/make-fixture.php > examples/app.log
 *   php paste-safe.php examples/app.log
 */

$email = 'ada' . '@' . 'example.com';
$ip = '203.0.113.10';
$jwt = 'eyJhbGciOiJIUzI1NiJ9' . '.' . 'eyJzdWIiOiIxMjM0In0' . '.' . 'dGVzdHNpZ25hdHVyZQ';
$stripe = 'sk_live_' . str_repeat('b', 24);
$aws = 'AKIA' . str_repeat('Z', 16);
$github = 'ghp_' . str_repeat('a', 36);
$password = 'correct-horse-battery';
$card = '4242' . '4242' . '4242' . '4242';

echo implode("\n", [
    '2026-10-28T20:00:00Z level=info msg="user login" user=' . $email . ' ip=' . $ip,
    'Authorization: Bearer ' . $jwt,
    'AWS_ACCESS_KEY_ID=' . $aws,
    'STRIPE_SECRET=' . $stripe,
    'GITHUB_TOKEN=' . $github,
    'DATABASE_URL=postgres://app:' . $password . '@db.internal:5432/app',
    'DB_PASSWORD=' . $password,
    'card=' . $card,
    'listen=127.0.0.1:8080',
    '',
]);
