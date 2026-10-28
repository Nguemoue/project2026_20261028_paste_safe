<?php

declare(strict_types=1);

require dirname(__DIR__) . '/paste-safe.php';

$ok = 0;
$fails = 0;

function check(bool $cond, string $message): void
{
    global $ok, $fails;
    if ($cond) {
        $ok++;
        return;
    }
    $fails++;
    fwrite(STDERR, "FAIL {$message}\n");
}

function eq(string $expected, string $actual, string $message): void
{
    global $ok, $fails;
    if ($expected === $actual) {
        $ok++;
        return;
    }
    $fails++;
    fwrite(STDERR, "FAIL {$message}\n--- expected ---\n{$expected}\n--- actual ---\n{$actual}\n");
}

/**
 * @param list<string> $args
 * @return array{0: int, 1: string, 2: string}
 */
function run_cli(array $args, string $stdin = ''): array
{
    $cmd = array_merge([PHP_BINARY, dirname(__DIR__) . '/paste-safe.php'], $args);
    $proc = proc_open($cmd, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if (!is_resource($proc)) {
        throw new RuntimeException('proc_open failed');
    }
    fwrite($pipes[0], $stdin);
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);

    return [proc_close($proc), $stdout === false ? '' : $stdout, $stderr === false ? '' : $stderr];
}

function secret_jwt(): string
{
    return 'eyJhbGciOiJIUzI1NiJ9' . '.' . 'eyJzdWIiOiIxMjM0In0' . '.' . 'dGVzdHNpZ25hdHVyZQ';
}

function secret_github(): string
{
    return 'ghp_' . str_repeat('a', 36);
}

function secret_github_pat(): string
{
    return 'github_pat_' . str_repeat('b', 22);
}

function secret_gitlab(): string
{
    return 'glpat-' . str_repeat('c', 20);
}

function secret_slack(): string
{
    return 'xoxb-' . str_repeat('1', 12) . '-' . str_repeat('d', 12);
}

function secret_stripe(): string
{
    return 'sk_test_' . str_repeat('e', 24);
}

function secret_aws(): string
{
    return 'AKIA' . str_repeat('Z', 16);
}

function secret_google(): string
{
    return 'AIza' . str_repeat('f', 35);
}

function secret_openai(): string
{
    return 'sk-' . str_repeat('g', 32);
}

function secret_sendgrid(): string
{
    return 'SG.' . str_repeat('h', 22) . '.' . str_repeat('i', 22);
}

function secret_npm(): string
{
    return 'npm_' . str_repeat('j', 36);
}

function secret_card(): string
{
    return '4242' . '4242' . '4242' . '4242';
}

function secret_card_bad(): string
{
    return '4242' . '4242' . '4242' . '4241';
}

$email = 'ada' . '@' . 'example.com';
$publicIp = '203.0.113.10';
$ipv6 = '2001:db8::1';
$dbPass = 's3cr3t-db-pass';
$apiPassword = 'correct-horse-battery';

$clean = "php 8.3.33 started at 10:30:00 build-1234 mac=00:1A:2B:3C:4D:5E listen=127.0.0.1:8080 bind=0.0.0.0\n";
$cleanResult = paste_safe_redact($clean);
eq($clean, $cleanResult['text'], 'harmless log is unchanged');
check($cleanResult['total'] === 0, 'harmless log has zero hits');

$log = implode("\n", [
    "user={$email} ip={$publicIp} v6={$ipv6}",
    'Authorization: Bearer ' . secret_jwt(),
    'Authorization: Bearer ' . str_repeat('o', 24),
    'GITHUB=' . secret_github(),
    'FINE=' . secret_github_pat(),
    'GL=' . secret_gitlab(),
    'SLACK=' . secret_slack(),
    'STRIPE=' . secret_stripe(),
    'AWS=' . secret_aws(),
    'GOOGLE=' . secret_google(),
    'OPENAI=' . secret_openai(),
    'SENDGRID=' . secret_sendgrid(),
    'NPM=' . secret_npm(),
    'DATABASE_URL=postgres://app:' . $dbPass . '@db.internal:5432/app',
    'DB_PASSWORD=' . $apiPassword,
    'API_KEY=example',
    'card=' . secret_card(),
    'notcard=' . secret_card_bad(),
    'webhook=https://hooks.slack.com/services/' . str_repeat('T', 9) . '/' . str_repeat('B', 9) . '/' . str_repeat('k', 24),
    'discord=https://discord.com/api/webhooks/123456789012345678/' . str_repeat('m', 24),
    'Authorization: Basic ' . base64_encode('app:' . $apiPassword),
    "loopback=127.0.0.1",
    "-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----",
    '',
]);

$result = paste_safe_redact($log);
$text = $result['text'];

foreach ([
    secret_jwt(), secret_github(), secret_github_pat(), secret_gitlab(), secret_slack(),
    secret_stripe(), secret_aws(), secret_google(), secret_openai(), secret_sendgrid(),
    secret_npm(), $dbPass, $apiPassword, secret_card(), $email, $publicIp, $ipv6,
] as $secret) {
    check(!str_contains($text, $secret), 'secret absent from output');
}

check(str_contains($text, '[REDACTED:jwt]'), 'jwt marker');
check(str_contains($text, '[REDACTED:github-token]'), 'github marker');
check(str_contains($text, '[REDACTED:gitlab-token]'), 'gitlab marker');
check(str_contains($text, '[REDACTED:slack-token]'), 'slack marker');
check(str_contains($text, '[REDACTED:stripe-key]'), 'stripe marker');
check(str_contains($text, '[REDACTED:aws-access-key]'), 'aws marker');
check(str_contains($text, '[REDACTED:google-api-key]'), 'google marker');
check(str_contains($text, '[REDACTED:openai-key]'), 'openai marker');
check(str_contains($text, '[REDACTED:sendgrid-key]'), 'sendgrid marker');
check(str_contains($text, '[REDACTED:npm-token]'), 'npm marker');
check(str_contains($text, 'postgres://app:[REDACTED:url-password]@db.internal:5432/app'), 'url user and host kept');
check(str_contains($text, 'DB_PASSWORD=[REDACTED:assignment]'), 'assignment keeps the key');
check(str_contains($text, 'API_KEY=example'), 'placeholder assignment kept');
check(str_contains($text, '[REDACTED:credit-card]'), 'luhn card redacted');
check(str_contains($text, 'notcard=' . secret_card_bad()), 'failed luhn kept');
check(str_contains($text, '[REDACTED:slack-webhook]'), 'slack webhook');
check(str_contains($text, '[REDACTED:discord-webhook]'), 'discord webhook');
check(str_contains($text, 'Authorization: Basic [REDACTED:basic-auth]'), 'basic auth');
check(str_contains($text, 'Authorization: Bearer [REDACTED:jwt]'), 'jwt bearer becomes jwt marker');
check(str_contains($text, 'Authorization: Bearer [REDACTED:bearer]'), 'opaque bearer label kept');
check(!str_contains($text, str_repeat('o', 24)), 'opaque bearer removed');
check(str_contains($text, '[REDACTED:private-key]'), 'pem removed');
check(!str_contains($text, 'BEGIN PRIVATE KEY'), 'pem header gone');
check(str_contains($text, 'loopback=127.0.0.1'), 'loopback kept');
check(($result['counts']['email'] ?? 0) === 1, 'one email');
check(($result['counts']['ipv4'] ?? 0) === 1, 'one public ipv4');
check(($result['counts']['ipv6'] ?? 0) === 1, 'one ipv6');

$kept = paste_safe_redact($log, ['keep_emails' => true, 'keep_ips' => true, 'keep_cards' => true]);
check(str_contains($kept['text'], $email), 'keep emails');
check(str_contains($kept['text'], $publicIp), 'keep ipv4');
check(str_contains($kept['text'], $ipv6), 'keep ipv6');
check(str_contains($kept['text'], secret_card()), 'keep cards');
check(!str_contains($kept['text'], secret_stripe()), 'secrets still removed when PII is kept');

$twice = paste_safe_redact($text);
check($twice['total'] === 0, 'second pass is a no-op');
eq($text, $twice['text'], 'second pass text is stable');

$quoted = paste_safe_redact('{"password": "' . $apiPassword . '"}');
eq('{"password": "[REDACTED:assignment]"}', $quoted['text'], 'json password');

$single = paste_safe_redact("note user={$email} done");
eq('note user=[REDACTED:email] done', $single['text'], 'surrounding text preserved');

$self = file_get_contents(dirname(__DIR__) . '/paste-safe.php');
check(is_string($self), 'source readable');
$selfResult = paste_safe_redact($self === false ? '' : $self);
check($selfResult['total'] === 0, 'tool source has no false positives: ' . paste_safe_summary($selfResult));

[$code, $stdout, $stderr] = run_cli([], "hello {$email}\n");
check($code === 0, 'default exit is 0 even when redacting');
eq("hello [REDACTED:email]\n", $stdout, 'stdin redacted on stdout');
check(str_contains($stderr, 'email=1'), 'summary on stderr');
check(!str_contains($stdout, $email) && !str_contains($stderr, $email), 'cli hides the raw email');

[$code, $stdout, $stderr] = run_cli(['--check', '--quiet'], "token=" . secret_jwt());
check($code === 2, 'check exit 2');
eq('', $stdout, 'check prints no body');
check(!str_contains($stderr, secret_jwt()), 'check stderr hides the secret');

[$code, $stdout] = run_cli(['--check', '--quiet'], "all good\n");
check($code === 0, 'clean check exits 0');
eq('', $stdout, 'clean check prints nothing');

[$code, $stdout, $stderr] = run_cli(['--json', '--check'], "ip={$publicIp} {$email}");
check($code === 2, 'json check exit 2');
$decoded = json_decode($stdout, true);
check(is_array($decoded), 'json decodes');
check(($decoded['total'] ?? 0) === 2, 'json total');
check(($decoded['counts']['email'] ?? 0) === 1 && ($decoded['counts']['ipv4'] ?? 0) === 1, 'json counts');
check(!array_key_exists('redacted', $decoded), 'json check omits body');
check(!str_contains($stdout, $email) && !str_contains($stderr, $email), 'json check hides email');

$tmp = tempnam(sys_get_temp_dir(), 'paste-safe-');
if ($tmp === false) {
    throw new RuntimeException('tempnam failed');
}
$outFile = $tmp . '.out';
file_put_contents($tmp, "ping {$email}\n");
[$code, $stdout, $stderr] = run_cli(['--quiet', '--out', $outFile, $tmp]);
check($code === 0, 'file mode exit 0');
eq('', $stdout, 'file mode writes no stdout');
eq("ping [REDACTED:email]\n", (string) file_get_contents($outFile), 'out file redacted');
unlink($tmp);
unlink($outFile);

[$code, $stdout] = run_cli(['--version']);
check($code === 0 && str_contains($stdout, PASTE_SAFE_VERSION), 'version');

[$code] = run_cli(['--nope']);
check($code === 1, 'unknown option exits 1');

[$code] = run_cli(['/no/such/paste-safe-file']);
check($code === 1, 'missing file exits 1');

if ($fails > 0) {
    fwrite(STDERR, "{$fails} failed, {$ok} passed\n");
    exit(1);
}

fwrite(STDOUT, "OK {$ok} assertions\n");
