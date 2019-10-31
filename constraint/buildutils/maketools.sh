#!/usr/bin/env bash

go get sigs.k8s.io/controller-tools/cmd/controller-gen@v0.1.8
go get k8s.io/code-generator/cmd/client-gen@93d7507fc8ffb4c860e4dd6f9a51a5e1985aebcd
go get k8s.io/code-generator/cmd/deepcopy-gen@93d7507fc8ffb4c860e4dd6f9a51a5e1985aebcd
go get k8s.io/code-generator/cmd/conversion-gen@93d7507fc8ffb4c860e4dd6f9a51a5e1985aebcd

mkdir /.output/buildutil
cp /go/bin/* /.output/buildutil/.