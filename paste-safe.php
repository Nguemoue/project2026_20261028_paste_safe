#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * paste-safe — redact secrets and PII from text before you paste it.
 *
 * One file, PHP >= 8.1, zero dependencies. Best-effort filter for logs and
 * support bundles, not a substitute for a git secret scanner.
 *
 * MIT License. Copyright (c) 2026 Luc (Nguemoue).
 */

const PASTE_SAFE_VERSION = '1.0.0';

/**
 * @param array{keep_emails?: bool, keep_ips?: bool, keep_cards?: bool} $options
 * @return array{text: string, counts: array<string, int>, total: int}
 */
function paste_safe_redact(string $text, array $options = []): array
{
    $keepEmails = (bool) ($options['keep_emails'] ?? false);
    $keepIps = (bool) ($options['keep_ips'] ?? false);
    $keepCards = (bool) ($options['keep_cards'] ?? false);
    $counts = [];

    $text = paste_safe_apply(
        $text,
        'private-key',
        '/-----BEGIN [A-Z0-9 ]*?PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*?PRIVATE KEY-----/',
        $counts
    );

    $text = paste_safe_apply(
        $text,
        'jwt',
        '/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/',
        $counts
    );

    $text = paste_safe_apply(
        $text,
        'github-token',
        '/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b/',
        $counts
    );

    $text = paste_safe_apply(
        $text,
        'gitlab-token',
        '/\bglpat-[A-Za-z0-9\-_]{20,}\b/',
        $counts
    );

    $text = paste_safe_apply(
        $text,
        'slack-token',
        '/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/',
        $counts
    );

    $text = paste_safe_apply(
        $text,
        'slack-webhook',
        '#https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+#i',
        $counts
    );

    $text = paste_safe_apply(
        $text,
        'discord-webhook',
        '#https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+#i',
        $counts
    );

    $text = paste_safe_apply(
        $text,
        'stripe-key',
        '/\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/',
        $counts
    );

    $text = paste_safe_apply(
        $text,
        'openai-key',
        '/\bsk-(?:proj-|ant-)?[A-Za-z0-9_\-]{20,}\b/',
        $counts
    );

    $text = paste_safe_apply(
        $text,
        'google-api-key',
        '/\bAIza[0-9A-Za-z\-_]{35}\b/',
        $counts
    );

    $text = paste_safe_apply(
        $text,
        'aws-access-key',
        '/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/',
        $counts
    );

    $text = paste_safe_apply(
        $text,
        'sendgrid-key',
        '/\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b/',
        $counts
    );

    $text = paste_safe_apply(
        $text,
        'npm-token',
        '/\bnpm_[A-Za-z0-9]{36}\b/',
        $counts
    );

    $text = paste_safe_apply(
        $text,
        'bearer',
        '/\b(Bearer\s+)([A-Za-z0-9\-._~+\/=]{12,})/i',
        $counts,
        static fn (array $m): string => $m[1] . '[REDACTED:bearer]'
    );

    $text = paste_safe_apply(
        $text,
        'basic-auth',
        '/\b(Basic\s+)([A-Za-z0-9+\/=]{8,})/i',
        $counts,
        static fn (array $m): string => $m[1] . '[REDACTED:basic-auth]'
    );

    $text = paste_safe_apply(
        $text,
        'url-password',
        '#([a-z][a-z0-9+.\-]*://)([^\s/:@]+):([^\s/@]{4,})@#i',
        $counts,
        static function (array $m): ?string {
            if (str_starts_with($m[3], '[REDACTED:') || paste_safe_is_placeholder($m[3])) {
                return null;
            }

            return $m[1] . $m[2] . ':[REDACTED:url-password]@';
        }
    );

    $text = paste_safe_redact_assignments($text, $counts);

    if (!$keepEmails) {
        $text = paste_safe_apply(
            $text,
            'email',
            '/(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}(?![A-Za-z0-9.\-])/',
            $counts
        );
    }

    if (!$keepIps) {
        $text = paste_safe_apply(
            $text,
            'ipv6',
            '/(?<![A-Fa-f0-9:])(?:(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,7}:|(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,5}(?::[A-Fa-f0-9]{1,4}){1,2}|(?:[A-Fa-f0-9]{1,4}:){1,4}(?::[A-Fa-f0-9]{1,4}){1,3}|(?:[A-Fa-f0-9]{1,4}:){1,3}(?::[A-Fa-f0-9]{1,4}){1,4}|(?:[A-Fa-f0-9]{1,4}:){1,2}(?::[A-Fa-f0-9]{1,4}){1,5}|[A-Fa-f0-9]{1,4}:(?::[A-Fa-f0-9]{1,4}){1,6}|:(?::[A-Fa-f0-9]{1,4}){1,7})(?![A-Fa-f0-9:])/',
            $counts,
            static function (array $m): ?string {
                if ($m[0] === '::1') {
                    return null;
                }

                return '[REDACTED:ipv6]';
            }
        );

        $text = paste_safe_apply(
            $text,
            'ipv4',
            '/(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\w.])/',
            $counts,
            static function (array $m): ?string {
                if (in_array($m[0], ['0.0.0.0', '127.0.0.1', '255.255.255.255'], true)) {
                    return null;
                }

                return '[REDACTED:ipv4]';
            }
        );
    }

    if (!$keepCards) {
        $text = paste_safe_apply(
            $text,
            'credit-card',
            '/(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)/',
            $counts,
            static function (array $m): ?string {
                $digits = preg_replace('/\D/', '', $m[0]) ?? '';
                $len = strlen($digits);
                if ($len < 13 || $len > 19 || !paste_safe_luhn($digits)) {
                    return null;
                }

                return '[REDACTED:credit-card]';
            }
        );
    }

    ksort($counts);

    return [
        'text' => $text,
        'counts' => $counts,
        'total' => array_sum($counts),
    ];
}

/**
 * @param array<string, int> $counts
 * @param null|callable(array<int|string, string>): (?string) $replace
 */
function paste_safe_apply(string $text, string $kind, string $pattern, array &$counts, ?callable $replace = null): string
{
    $result = preg_replace_callback(
        $pattern,
        static function (array $m) use ($kind, &$counts, $replace): string {
            if ($replace !== null) {
                $next = $replace($m);
                if ($next === null) {
                    return $m[0];
                }
                $counts[$kind] = ($counts[$kind] ?? 0) + 1;

                return $next;
            }

            $counts[$kind] = ($counts[$kind] ?? 0) + 1;

            return '[REDACTED:' . $kind . ']';
        },
        $text
    );

    if (!is_string($result)) {
        throw new RuntimeException('Pattern failed for ' . $kind . ' (' . preg_last_error_msg() . ')');
    }

    return $result;
}

/**
 * @param array<string, int> $counts
 */
function paste_safe_redact_assignments(string $text, array &$counts): string
{
    $pattern = '/(?i)(["\']?)([A-Za-z_][A-Za-z0-9_.-]{1,80})\1\s*[:=]\s*(["\'])?([^\s"\',;&]{8,200})/';
    $result = preg_replace_callback(
        $pattern,
        static function (array $m) use (&$counts): string {
            $key = $m[2];
            $value = $m[4];
            if (!paste_safe_is_sensitive_key($key) || paste_safe_is_placeholder($value) || str_starts_with($value, '[REDACTED:')) {
                return $m[0];
            }

            $counts['assignment'] = ($counts['assignment'] ?? 0) + 1;
            $full = $m[0];
            $pos = strrpos($full, $value);
            if ($pos === false) {
                return $m[0];
            }

            return substr($full, 0, $pos) . '[REDACTED:assignment]' . substr($full, $pos + strlen($value));
        },
        $text
    );

    if (!is_string($result)) {
        throw new RuntimeException('Pattern failed for assignment (' . preg_last_error_msg() . ')');
    }

    return $result;
}

function paste_safe_is_sensitive_key(string $key): bool
{
    return (bool) preg_match(
        '/(?:^|[-_.])(?:passwords?|passwds?|pwds?|secrets?|tokens?|api[-_]?keys?|access[-_]?keys?|private[-_]?keys?|credentials?)(?:$|[-_.])/i',
        $key
    );
}

function paste_safe_is_placeholder(string $value): bool
{
    $normalized = strtolower(trim($value, "\"'"));
    $exact = [
        'password', 'passwd', 'secret', 'changeme', 'changeit', 'example',
        'examples', 'xxx', 'xxxx', 'xxxxx', 'redacted', 'null', 'none', 'nil',
        'true', 'false', 'undefined', 'todo', 'placeholder', 'dummy', 'test',
        'testing', 'your-password', 'your_password', 'your-api-key', 'your_api_key',
        '<password>', '<secret>',
    ];

    if (in_array($normalized, $exact, true)) {
        return true;
    }

    if (preg_match('/^(?:\*+|x{3,}|<[^>]{1,40}>|\$\{[^}]{1,80}\}|\{\{[^}]{1,80}\}\}|\[redacted[^\]]*\])$/i', $value) === 1) {
        return true;
    }

    return preg_match('/^(?:your|my|example|sample|dummy|placeholder)[-_]/i', $value) === 1;
}

function paste_safe_luhn(string $digits): bool
{
    $sum = 0;
    $alt = false;
    for ($i = strlen($digits) - 1; $i >= 0; $i--) {
        $n = ord($digits[$i]) - 48;
        if ($n < 0 || $n > 9) {
            return false;
        }
        if ($alt) {
            $n *= 2;
            if ($n > 9) {
                $n -= 9;
            }
        }
        $sum += $n;
        $alt = !$alt;
    }

    return $sum % 10 === 0;
}

/**
 * @param array{text: string, counts: array<string, int>, total: int} $result
 */
function paste_safe_summary(array $result): string
{
    if ($result['total'] === 0) {
        return 'paste-safe: nothing to redact';
    }

    $parts = [];
    foreach ($result['counts'] as $kind => $n) {
        $parts[] = $kind . '=' . $n;
    }
    $noun = $result['total'] === 1 ? 'item' : 'items';

    return 'paste-safe: redacted ' . $result['total'] . ' ' . $noun . ': ' . implode(', ', $parts);
}

function paste_safe_help(): string
{
    return 'paste-safe ' . PASTE_SAFE_VERSION . ' — redact secrets before you paste a log.' . "\n"
        . "\n"
        . "Usage:\n"
        . "  php paste-safe.php [options] [file]\n"
        . "  cat app.log | php paste-safe.php\n"
        . "\n"
        . "Options:\n"
        . "  -o, --out <file>   Write the redacted text to a file\n"
        . "  -c, --check        Print no text body. Exit 2 if anything was redacted\n"
        . "  -j, --json         JSON report on stdout (text included unless --check)\n"
        . "  -q, --quiet        Suppress the stderr summary\n"
        . "      --keep-emails  Do not redact email addresses\n"
        . "      --keep-ips     Do not redact IP addresses\n"
        . "      --keep-cards   Do not redact payment card numbers\n"
        . "  -V, --version      Print version\n"
        . "  -h, --help         Show this help\n"
        . "\n"
        . "Exit codes:\n"
        . "  0  success, or a clean file when --check is set\n"
        . "  2  --check found something sensitive\n"
        . "  1  usage or IO error\n"
        . "\n"
        . "The default mode always exits 0 after a successful redact, so a pipe\n"
        . "into pbcopy or a ticket stays usable. Use --check in CI.\n";
}

function paste_safe_main(array $argv): int
{
    $out = null;
    $check = false;
    $json = false;
    $quiet = false;
    $keepEmails = false;
    $keepIps = false;
    $keepCards = false;
    $file = null;

    $args = array_slice($argv, 1);
    $count = count($args);
    for ($i = 0; $i < $count; $i++) {
        $arg = $args[$i];
        switch ($arg) {
            case '-h':
            case '--help':
                fwrite(STDOUT, paste_safe_help());
                return 0;
            case '-V':
            case '--version':
                fwrite(STDOUT, 'paste-safe ' . PASTE_SAFE_VERSION . "\n");
                return 0;
            case '-c':
            case '--check':
                $check = true;
                break;
            case '-j':
            case '--json':
                $json = true;
                break;
            case '-q':
            case '--quiet':
                $quiet = true;
                break;
            case '--keep-emails':
                $keepEmails = true;
                break;
            case '--keep-ips':
                $keepIps = true;
                break;
            case '--keep-cards':
                $keepCards = true;
                break;
            case '-o':
            case '--out':
                $i++;
                if (!isset($args[$i]) || str_starts_with($args[$i], '-')) {
                    fwrite(STDERR, "paste-safe: missing value for {$arg}\n");
                    return 1;
                }
                $out = $args[$i];
                break;
            case '--':
                if (isset($args[$i + 1])) {
                    if ($file !== null || isset($args[$i + 2])) {
                        fwrite(STDERR, "paste-safe: too many arguments\n");
                        return 1;
                    }
                    $file = $args[$i + 1];
                }
                $i = $count;
                break;
            default:
                if (str_starts_with($arg, '-')) {
                    fwrite(STDERR, "paste-safe: unknown option {$arg}\n");
                    return 1;
                }
                if ($file !== null) {
                    fwrite(STDERR, "paste-safe: too many arguments\n");
                    return 1;
                }
                $file = $arg;
        }
    }

    if ($file === '-') {
        $file = null;
    }

    if ($file === null && stream_isatty(STDIN)) {
        fwrite(STDERR, paste_safe_help());
        return 1;
    }

    if ($file !== null && !is_file($file)) {
        fwrite(STDERR, "paste-safe: cannot read {$file}\n");
        return 1;
    }

    $input = $file === null ? stream_get_contents(STDIN) : file_get_contents($file);
    if ($input === false) {
        fwrite(STDERR, "paste-safe: failed to read input\n");
        return 1;
    }

    try {
        $result = paste_safe_redact($input, [
            'keep_emails' => $keepEmails,
            'keep_ips' => $keepIps,
            'keep_cards' => $keepCards,
        ]);
    } catch (Throwable $e) {
        fwrite(STDERR, 'paste-safe: ' . $e->getMessage() . "\n");
        return 1;
    }

    if ($out !== null && file_put_contents($out, $result['text']) === false) {
        fwrite(STDERR, "paste-safe: cannot write {$out}\n");
        return 1;
    }

    if ($json) {
        $payload = [
            'version' => PASTE_SAFE_VERSION,
            'total' => $result['total'],
            'counts' => $result['counts'] === [] ? new stdClass() : $result['counts'],
        ];
        if (!$check) {
            $payload['redacted'] = $result['text'];
        }
        $encoded = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($encoded === false) {
            fwrite(STDERR, "paste-safe: failed to encode JSON\n");
            return 1;
        }
        fwrite(STDOUT, $encoded . "\n");
    } elseif (!$check && $out === null) {
        fwrite(STDOUT, $result['text']);
    }

    if (!$quiet && !$json) {
        fwrite(STDERR, paste_safe_summary($result) . "\n");
    }

    if ($check && $result['total'] > 0) {
        return 2;
    }

    return 0;
}

if (PHP_SAPI === 'cli' && realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === realpath(__FILE__)) {
    exit(paste_safe_main($argv));
}
