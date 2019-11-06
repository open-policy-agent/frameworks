#!/usr/bin/env bash

echo 'Starting tool build...'

echo 'controller-gen'
go get sigs.k8s.io/controller-tools/cmd/controller-gen@v0.1.8

echo 'client-gen'
go get k8s.io/code-generator/cmd/client-gen@93d7507fc8ffb4c860e4dd6f9a51a5e1985aebcd

echo 'deepcopy-gen'
go get k8s.io/code-generator/cmd/deepcopy-gen@93d7507fc8ffb4c860e4dd6f9a51a5e1985aebcd

echo 'conversion-gen'
go get k8s.io/code-generator/cmd/conversion-gen@93d7507fc8ffb4c860e4dd6f9a51a5e1985aebcd

mkdir /.output/buildutil
chmod 755 /.output/buildutil
cp /go/bin/* /.output/buildutil/.

echo 'Contents of /.output/buildutil are:'
ls -l /.output/buildutil