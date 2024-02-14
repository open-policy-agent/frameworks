# When updating this, make sure to update the corresponding action in
# workflow.yaml
GOLANGCI_LINT_VERSION ?= 1.50.0
KUSTOMIZE_VERSION ?= 3.8.9
KUBERNETES_VERSION ?= 1.26.0

# Detects the location of the user golangci-lint cache.
GOLANGCI_LINT_CACHE := $(shell pwd)/.tmp/golangci-lint

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
native-test: gen-dependencies manifests envtest
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(KUBERNETES_VERSION) --bin-dir $(LOCALBIN) -p path)" \
	GO111MODULE=on \
	go test -mod vendor ./pkg/... -race -bench . -coverprofile cover.out

# Hook to run docker tests
.PHONY: test
test: __test-image
	docker run --rm -v $(shell pwd):/app constraint-test make native-test

# Install CRDs into a cluster
install: manifests
	kubectl apply -f config/crds

# Install the generation dependencies on the local machine
gen-dependencies:
	go install sigs.k8s.io/controller-tools/cmd/controller-gen@v0.10.0
	go install k8s.io/code-generator/cmd/conversion-gen@v0.25.4
	go install k8s.io/code-generator/cmd/defaulter-gen@v0.25.4

# Generate manifests e.g. CRD, RBAC etc.
manifests:
	controller-gen \
		crd:allowDangerousTypes="true" \
		paths="./pkg/..." \
		output:crd:artifacts:config=config/crds
	kustomize build config/crds --output=deploy/crds.yaml
	mkdir -p .staging/templatecrd
	cp config/crds/* .staging/templatecrd
	sed -i '/- externaldata.gatekeeper.sh_providers.yaml/d' .staging/templatecrd/kustomization.yaml
	kustomize build .staging/templatecrd --output=.staging/templatecrd/crd.yaml

# lint runs a dockerized golangci-lint, and should give consistent results
# across systems.
# Source: https://golangci-lint.run/usage/install/#docker
lint:
	docker run --rm -v $(shell pwd):/app \
		-v ${GOLANGCI_LINT_CACHE}:/root/.cache/golangci-lint \
		-w /app golangci/golangci-lint:v${GOLANGCI_LINT_VERSION}-alpine \
		golangci-lint run -v

# Generate code
# Not working?  Try running `make gen-dependencies`
generate: generate-defaults
	controller-gen \
		object:headerFile=./hack/boilerplate.go.txt \
		paths="./pkg/..."
	# This conversion-gen code is broken.  For some reason, it does not include functions
	# for converting from v1beta JSONSchemaProps to apiextensions JSONSchemaProps, even though
	# those functions exist and can be added manually to the conversion file.
	# TODO: Once https://github.com/kubernetes/kubernetes/issues/101567 is fixed, update
	# conversion-gen and get us back to running `make generate` in our CI pipeline
	conversion-gen \
		--input-dirs "./pkg/apis/templates/v1,./pkg/apis/templates/v1beta1,./pkg/apis/templates/v1alpha1,./pkg/apis/externaldata/v1alpha1,./pkg/apis/externaldata/v1beta1" \
		--output-base=./ \
		--go-header-file=./hack/boilerplate.go.txt \
		--output-file-base=zz_generated.conversion \
		--extra-dirs=k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1

CRD_SOURCE_FILE := deploy/crds.yaml
FILE_STUB := "package schema\
\n\
\n// This file is generated from $(CRD_SOURCE_FILE) via \"make constraint-template-string-constant\"\
\n// DO NOT MODIFY THIS FILE DIRECTLY!\
\n\
\nconst constraintTemplateCRDYaml = \`"

YAML_CONSTANT_GOLANG_FILE := ./pkg/schema/yaml_constant.go

constraint-template-string-constant: manifests
	rm -rf $(YAML_CONSTANT_GOLANG_FILE)
	bash -c 'echo -en ${FILE_STUB} >> ${YAML_CONSTANT_GOLANG_FILE}'
	bash -c 'cat .staging/templatecrd/crd.yaml >> ${YAML_CONSTANT_GOLANG_FILE}'
	bash -c 'echo "\`" >> ${YAML_CONSTANT_GOLANG_FILE}'
	# Remove trailing spaces.  Double $ is to prevent variable expansion in make
	sed -i "s/ $$//g" ${YAML_CONSTANT_GOLANG_FILE}
	rm -rf .staging

generate-defaults: constraint-template-string-constant
	defaulter-gen \
		--input-dirs "./pkg/apis/templates/..." \
		--go-header-file=./hack/boilerplate.go.txt \
		--output-file-base=zz_generated.defaults

.PHONY: vendor
vendor:
	go mod vendor
	go mod tidy

.PHONY: __test-image
__test-image:
	docker buildx build . \
		-t constraint-test \
		--load \
		--build-arg KUSTOMIZE_VERSION=$(KUSTOMIZE_VERSION)

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/.tmp/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

ENVTEST ?= $(LOCALBIN)/setup-envtest

.PHONY: envtest
envtest: $(ENVTEST) ## Download envtest-setup locally if necessary.
$(ENVTEST): $(LOCALBIN)
	test -s $(LOCALBIN)/setup-envtest || GOBIN=$(LOCALBIN) GCO_ENABLED=0 go install sigs.k8s.io/controller-runtime/tools/setup-envtest@v0.0.0-20230118154835-9241bceb3098
