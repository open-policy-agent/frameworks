all: test

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

all: lint test

# Run tests
native-test: generate fmt vet manifests
	go test ./pkg/... -coverprofile cover.out

# Docker internal test
docker-internal-test:
	make native-test
# The remote driver has some unimplemented functions
# which result in a panic during testing.
#	./tests/test_remote_driver.sh

# Hook to run docker tests
test: generate
	docker build . -t constraint-test && docker run -t constraint-test

# Install CRDs into a cluster
install: manifests
	kubectl apply -f config/crds

# Generate manifests e.g. CRD, RBAC etc.
manifests: buildutils
	controller-gen all
	kustomize build config -o deploy/crds.yaml

# Run go fmt against code
fmt:
	go fmt ./pkg/...

# Run go vet against code
vet:
	go vet ./pkg/...

lint:
	golangci-lint -v run ./... --timeout 5m

# Generate code
generate: buildutils
ifndef GOPATH
	$(error GOPATH not defined, please define GOPATH. Run "go help gopath" to learn more about GOPATH)
endif
	export GOROOT=$(go env root)
	GO111MODULE=off go generate ./pkg/...

# find or download controller-gen
# download controller-gen if necessary
.PHONY: buildutils
buildutils:
	cd buildutils && ./buildutils.sh

