# Security policy

stackward runs as root on production servers, so we treat security reports
as the highest priority.

## Reporting a vulnerability

Please do not open a public issue. Report privately through GitHub:
open the repository's **Security** tab and choose **Report a vulnerability**
(GitHub private vulnerability reporting). You will get an answer within a
few days.

Useful to include: the version (`stackward version`), the distribution, what
you ran, and what happened. Do not attach a real report or facts dump from a
production host unless you have checked it; `--dump-facts` output is redacted,
but you know your host best.

## What counts

Anything that breaks the read only promise in the README is a vulnerability:

- stackward writing, deleting or changing anything other than the `--out`
  file;
- sending a non GET request to Docker, or running a command that changes
  state;
- reading secret file contents, or a secret value reaching any output
  (report, `--dump-facts`, errors);
- the sandbox reporting `landlock` while not actually confining the process;
- any network traffic from `stackward audit`.

A check that gives a wrong verdict is a bug, and a serious one when it says
pass where it should fail; please report those as issues unless the details
would help an attacker.

## Supported versions

Only the latest release receives fixes while stackward is pre 1.0.
