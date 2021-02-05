#!/usr/bin/env bash

set -euo pipefail

cd $(dirname $0)/..

# go mod vendor

set -x
go run vendor/k8s.io/code-generator/cmd/deepcopy-gen/main.go \
  --output-file-base zz_generated.deepcopy \
  --input-dirs github.com/open-policy-agent/frameworks/constraint/pkg/apis/... \
  --go-header-file hack/boilerplate.go.txt

go run vendor/k8s.io/code-generator/cmd/conversion-gen/main.go \
  --output-file-base zz_generated.conversion \
  --input-dirs github.com/open-policy-agent/frameworks/constraint/pkg/apis/... \
  --go-header-file hack/boilerplate.go.txt

go run vendor/k8s.io/code-generator/cmd/deepcopy-gen/main.go \
  --output-file-base zz_generated.deepcopy \
  --input-dirs github.com/open-policy-agent/frameworks/constraint/pkg/core/templates/... \
  --go-header-file hack/boilerplate.go.txt

go run vendor/sigs.k8s.io/controller-tools/cmd/controller-gen/main.go \
  crd \
  paths=./pkg/apis/templates/...

# rm -rf vendor
