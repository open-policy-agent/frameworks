#!/usr/bin/env bash

export GO111MODULE=on

echo 'Starting tool build...'

set -x
go get sigs.k8s.io/controller-tools/cmd/controller-gen@v0.4.1
go get k8s.io/code-generator/cmd/client-gen@v0.20.2
go get k8s.io/code-generator/cmd/deepcopy-gen@v0.20.2
go get k8s.io/code-generator/cmd/conversion-gen@v0.20.2
