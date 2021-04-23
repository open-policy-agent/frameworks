all: test

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

all: lint test

# Run tests
# TODO: Once https://github.com/kubernetes/kubernetes/issues/101567 is fixed, add `generate` back as a dependency target
native-test: gen-dependencies manifests
	go test ./pkg/... -coverprofile cover.out

# Docker internal test
docker-internal-test:
	make native-test
# The remote driver has some unimplemented functions
# which result in a panic during testing.
#	./tests/test_remote_driver.sh

# Hook to run docker tests
test:
	docker build . -t constraint-test && docker run -t constraint-test

# Install CRDs into a cluster
install: manifests
	kubectl apply -f config/crds

# Install the generation dependencies on the local machine
gen-dependencies:
	GO111MODULE=on go get sigs.k8s.io/controller-tools/cmd/controller-gen@v0.5.0
	GO111MODULE=on go get k8s.io/code-generator/cmd/conversion-gen@v0.20.2

# Generate manifests e.g. CRD, RBAC etc.
manifests:
	controller-gen \
		crd:crdVersions="v1beta1",allowDangerousTypes="true" \
		paths="./pkg/..." \
		output:crd:artifacts:config=config/crds
	cp config/crds/* deploy/crds.yaml

lint:
	golangci-lint -v run ./... --timeout 5m

# Generate code
# Not working?  Try running `make gen-dependencies`
generate:
	controller-gen \
		object:headerFile=./hack/boilerplate.go.txt \
		paths="./pkg/..."
	# This conversion-gen code is broken.  For some reason, it does not include functions
	# for converting from v1beta JSONSchemaProps to apiextensions JSONSchemaProps, even though
	# those functions exist and can be added manually to the conversion file.
	# TODO: Once https://github.com/kubernetes/kubernetes/issues/101567 is fixed, update
	# conversion-gen and get us back to running `make generate` in our CI pipeline
	conversion-gen \
		--input-dirs "./pkg/apis/templates/..." \
		--go-header-file=./hack/boilerplate.go.txt \
		--output-file-base=zz_generated.conversion \
		--extra-dirs=k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1
