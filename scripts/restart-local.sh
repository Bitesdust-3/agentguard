#!/usr/bin/env bash
set -euo pipefail

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

cd "$project_dir"
go build -o bin/agentguard ./cmd/agentguard
sudo systemctl restart agentguard
systemctl status agentguard --no-pager
curl --noproxy '*' --fail --silent --show-error http://127.0.0.1:18080/health
printf '\n'
