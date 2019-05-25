## recipientfilter
Validate incoming email usernames against a Secret. It will allow email addresses of the form `username.hash@doma.in`, where the hash are the first `N` hex bytes of `hmac<sha256>('username', secret)`. This allows using catch-all domains while reliably placing blame when receiving spam at one of these addresses.

## This repository contains two Programs:
* `recipient_filter/`: A Postfix SMTP access policy delegation server that validates receiver email addresses with a secret.
* `mailgen/`: A CLI tool that generates valid email addresses for `recipient_filter`.
