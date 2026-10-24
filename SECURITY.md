# Security policy

sshvault holds SSH keys and configuration, so a weakness in it can expose them. Please
report anything you find privately, not in a public issue.

## Reporting

Use GitHub's private vulnerability reporting:
<https://github.com/torstei/sshvault/security/advisories/new>. Include what an attacker
needs (which user, which process, what access), what they gain, and how to reproduce it.

You will get an answer within a week. Fixes are released as a new version in the apt
repository and announced in a GitHub security advisory, crediting the reporter unless
they prefer otherwise.

## Supported versions

Only the latest release gets security fixes. The apt repository always carries it, so
`apt upgrade` is the way to stay covered.

## Scope

In scope is anything that lets a process reach vault contents it should not: another
user's processes, the same user's processes outside an unlocked shell, a remote host
reached through ssh, or anyone reading the stored vault files. So is anything that lets
such a process deny service to other users.

The README's "What it does not do" section lists what is out of scope by design, such as
root and what runs inside an unlocked shell.
