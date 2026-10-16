# Cloud environment

## Environment variables

```
KRU_STORE_REPO=ap-justin/kru-store
```

## Network access

Custom, *include defaults* on, plus:

```
mcp.context7.com
astral.sh
```

## Setup script

```bash
#!/bin/bash
# kru v0.148.0
set -uo pipefail
exec > >(tee -a /tmp/setup.log) 2>&1

try() {
  for _ in 1 2 3; do "$@" && return 0; sleep 2; done
  echo "SETUP FAIL: $*"
}

# kru store
try git clone -q https://github.com/ap-justin/kru-store ~/.kru
[ -f ~/.kru/setup.sh ] && try bash ~/.kru/setup.sh

# plugins
try claude plugin marketplace add anthropics/claude-plugins-official
try claude plugin marketplace add ap-justin/kru
try claude plugin install kru@kru --scope user
try claude plugin enable cc-plugin-you-should-know@builtin --scope user

# bugsink-mcp: vm provisioning
try bash -c 'curl -LsSf https://astral.sh/uv/install.sh | sh'

node --version; claude plugin list
exit 0
```
