#!/usr/bin/env bash
# QA overlay: the dev loadtest runner loads devshard/testenv/config/config.yaml (the gitignored
# skeleton the README calls "Skeleton: config/config.yaml") and overrides topology, params, escrow
# amount and mock-ML nodes from the scenario. CI checkouts have no such file (the colleague's runs
# used a local one) → render the README default skeleton here: 3 hosts (versiond-0/1 HA pair +
# versiond-2 solo), postgres on, multi mode. Mirrors citest/harness/config.go WriteMultiConfig.
# Values the runner overrides (participants, max_nonce, escrow amount, ML nodes) are placeholders.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
cfg="${QA_SKELETON_PATH:-$here/../config/config.yaml}"
if [ -f "$cfg" ]; then echo "skeleton exists: $cfg"; exit 0; fi
cat > "$cfg" <<'YAML'
chain_id: gonka-test
block_height: 150
epoch:
  index: 1
  poc_start_block_height: 100
  epoch_length: 400
params:
  devshard_requests_enabled: true
mock_chain:
  grpc_port: 9090
  rpc_port: 26657
  testenv_port: 8090
mock_dapi:
  grpc_port: 9091
  http_port: 8081
mock_openai:
  http_port: 8088
ml_nodes: 1
versiond:
  mode: multi
  version_name: v2
  binary_version: 0.2.13-v2-r2
versiond_router:
  port: 8080
devshardctl:
  port: 8082
postgres:
  enabled: true
network:
  subnet: 172.31.0.0/24
  base_ip: 172.31.0
escrow:
  slots: 2
hosts:
  - id: versiond-0
    private_key_hex: TODO
  - id: versiond-1
    private_key_hex: TODO
  - id: versiond-2
    private_key_hex: TODO
user:
  private_key_hex: TODO
warm_grantee:
  private_key_hex: TODO
escrows:
  - id: 1
    model_id: test-model
grantees:
  - granter_address: ""
    message_type_url: /inference.inference.MsgStartInference
    grantees: [""]
YAML
echo "wrote skeleton $cfg"
