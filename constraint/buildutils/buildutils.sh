#!/usr/bin/env bash

echo 'Starting tool build...'

echo 'controller-gen'
GO111MODULE=on go get sigs.k8s.io/controller-tools/cmd/controller-gen@v0.4.1

echo 'client-gen'
GO111MODULE=on go get k8s.io/code-generator/cmd/client-gen@80a9312ce45a8da7ee04ac69c7caf62d7bc4f686

echo 'deepcopy-gen'
GO111MODULE=on go get k8s.io/code-generator/cmd/deepcopy-gen@80a9312ce45a8da7ee04ac69c7caf62d7bc4f686

echo 'conversion-gen'
GO111MODULE=on go get k8s.io/code-generator/cmd/conversion-gen@80a9312ce45a8da7ee04ac69c7caf62d7bc4f686
