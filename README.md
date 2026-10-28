# paste-safe

**Stop pasting secrets into Slack, GitHub or ChatGPT.**

One PHP file. No Composer. No extensions. Pipe a log in, get the same log back with API keys, tokens, passwords and obvious PII replaced by `[REDACTED:…]`.

**Arrête de coller des secrets dans Slack, GitHub ou ChatGPT.** Un seul fichier PHP, zéro dépendance : le log ressort identique, sans clés, tokens, mots de passe ni PII évidentes.

```bash
php paste-safe.php storage/logs/laravel.log | pbcopy
# paste-safe: redacted 6 items: bearer=1, email=1, ipv4=1, jwt=1, stripe-key=1, url-password=1
```

## Install

Requires PHP 8.1+.

```bash
curl -fsSL -o paste-safe.php https://raw.githubusercontent.com/Nguemoue/project2026_20261028_paste_safe/main/paste-safe.php
php paste-safe.php --help
```

Or clone this repo. `composer.json` only exists so `vendor/bin/paste-safe` works if you want it; nothing is installed from Packagist.

## Use

```bash
php paste-safe.php app.log                  # redacted text on stdout, summary on stderr
php paste-safe.php --out safe.log app.log   # write a file, leave stdout empty
php paste-safe.php --check app.log          # CI: exit 2 when something was found, print no body
php paste-safe.php --json --check app.log   # counts only, safe to keep in a job log
php paste-safe.php --keep-ips app.log       # still drop secrets, keep IP addresses
```

Try it on a fake log (the fixture is built in memory, it is not a real credential):

```bash
php examples/make-fixture.php | php paste-safe.php
```

Exit codes: `0` success, `2` only with `--check` when something was redacted, `1` usage or IO error. Default mode exits `0` on purpose, so `| pbcopy` does not break under `pipefail`.

## What it catches

| Marker | Examples |
| --- | --- |
| `private-key` | PEM blocks |
| `jwt` | three-segment `eyJ…` tokens |
| `github-token` | `ghp_`, `gho_`, `github_pat_`, … |
| `gitlab-token` | `glpat-` |
| `slack-token` / `slack-webhook` | `xoxb-` and `hooks.slack.com` URLs |
| `discord-webhook` | Discord webhook URLs |
| `stripe-key` | `sk_live_`, `sk_test_`, `pk_`, `rk_` |
| `openai-key` | `sk-`, `sk-proj-`, `sk-ant-` |
| `google-api-key` | `AIza…` |
| `aws-access-key` | `AKIA…`, `ASIA…` |
| `sendgrid-key` | `SG.…` |
| `npm-token` | `npm_…` |
| `bearer` / `basic-auth` | `Authorization` headers |
| `url-password` | `scheme://user:password@host` (user and host stay) |
| `assignment` | `PASSWORD`, `API_KEY`, `SECRET`, `TOKEN`, … when the value is at least 8 characters and not a placeholder like `example`, `changeme`, `${VAR}` |
| `email` | mailbox addresses (`--keep-emails` to skip) |
| `ipv4` / `ipv6` | public addresses; `127.0.0.1`, `0.0.0.0`, `255.255.255.255` and `::1` stay (`--keep-ips`) |
| `credit-card` | 13–19 digits that pass the Luhn check, with spaces or dashes (`--keep-cards`) |

Placeholders are stable: running paste-safe twice does not redact its own markers.

## CI

```yaml
- uses: shivammathur/setup-php@v2
  with:
    php-version: '8.3'
- name: Support bundle has no secrets
  run: php paste-safe.php --check support-bundle.log
```

This is the wrong tool for scanning git history. Use it on the blob you are about to paste, upload, or attach to a ticket.

## Limits

Best effort, not a guarantee. It will miss a secret that does not look like one, and it can redact a boring value whose name contains `token` or `secret`. Read the summary line. Do not disable your eyes.

Generic assignments ignore values shorter than 8 characters so `TOKEN_TYPE=Bearer` survives. Unquoted values stop at whitespace.

## Tests

```bash
php tests/redact_test.php
```

## Utilisation rapide

```bash
php paste-safe.php storage/logs/laravel.log
php paste-safe.php --check le-fichier-que-tu-allais-coller.log
```

Le texte nettoyé sort sur stdout. Le résumé (`jwt=1, email=2, …`) sort sur stderr, donc il n’est pas copié quand tu pipes vers le presse-papiers. `--check` n’imprime pas le log et renvoie `2` s’il a trouvé quelque chose : pratique juste avant d’ouvrir un ticket ou de coller un extrait dans un LLM.

## License

MIT. See [LICENSE](LICENSE).
