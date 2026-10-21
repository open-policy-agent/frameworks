# Agent Instructions for OPA Constraint Framework

## Project Overview

The OPA Constraint Framework is a Go library that provides opinionated APIs for policy enforcement on top of Open Policy Agent (OPA). It enables defining reusable policy templates (ConstraintTemplates) and instantiating them as Constraints. The primary consumer is [Gatekeeper](https://github.com/open-policy-agent/gatekeeper), a Kubernetes admission controller.

**Repository Details:**
- **Language:** Go 1.24+
- **Type:** Library/SDK for policy evaluation
- **Key Dependencies:** OPA (Rego engine), Kubernetes API machinery, controller-runtime
- **Build System:** Make with Docker for containerized lint/test
- **Main Code Location:** All source code is in the `constraint/` subdirectory

## Project Structure

```
frameworks/
├── constraint/                    # Main module - ALL development happens here
│   ├── Makefile                   # Primary build commands
│   ├── go.mod                     # Go module (github.com/open-policy-agent/frameworks/constraint)
│   ├── .golangci.yaml             # Linter configuration (golangci-lint v1.64.8)
│   ├── Dockerfile                 # Test container image
│   ├── pkg/                       # Source code
│   │   ├── apis/                  # Kubernetes API definitions (CRDs)
│   │   │   ├── templates/         # ConstraintTemplate API (v1, v1alpha1, v1beta1)
│   │   │   ├── externaldata/      # ExternalData provider API
│   │   │   └── constraints/       # Constraint helpers
│   │   ├── client/                # Main client interface for policy evaluation
│   │   │   ├── client.go          # Client type - primary entry point
│   │   │   ├── drivers/           # Policy engine drivers
│   │   │   │   ├── rego/          # OPA Rego driver (primary)
│   │   │   │   └── fake/          # Test driver
│   │   │   └── reviews/           # Review request options
│   │   ├── core/templates/        # Core template types
│   │   ├── handler/               # Target handler interface
│   │   └── types/                 # Shared types (Result, Response)
│   ├── config/crds/               # Generated CRD manifests
│   ├── deploy/                    # Deployment artifacts
│   ├── hack/                      # Build scripts (boilerplate.go.txt)
│   └── vendor/                    # Vendored dependencies (REQUIRED)
├── build/                         # Root build script
├── .github/workflows/             # CI pipelines
└── Makefile                       # Root Makefile (delegates to constraint/)
```

## Build & Development Commands

**CRITICAL:** Always work from the `constraint/` directory. The root Makefile simply delegates to `constraint/`.

### Prerequisites
- Go 1.24+ (CI uses Go 1.25)
- Docker with buildx support
- `kustomize` (installed automatically by gen-dependencies)
- `controller-gen` (installed automatically by gen-dependencies)

### Essential Commands (run from `constraint/` directory)

```bash
# Install code generation tools - RUN FIRST on fresh clone
make gen-dependencies

# Run unit tests natively (preferred for development, ~2-3 minutes)
make native-test

# Run tests in Docker container (~3-5 minutes)
make test

# Run linter (uses Docker, golangci-lint v1.64.8)
make lint

# Generate CRD manifests (run after API changes)
make manifests

# Update vendor directory (run after go.mod changes)
make vendor
```

### Command Execution Order

1. **Fresh clone:** `make gen-dependencies` → `make vendor` → `make native-test`
2. **After go.mod changes:** `make vendor` → `make native-test`
3. **After API changes:** `make manifests` → `make native-test`
4. **Before commit:** `make lint` → `make native-test`

### Common Issues & Solutions

- **Lint failures for formatting:** Run `make lint` with `--fix` flag (it auto-fixes by default)
- **Missing controller-gen:** Run `make gen-dependencies`
- **Vendor out of sync:** Run `go mod tidy && go mod vendor`
- **Comments must end with period:** godot linter requires comment sentences to end with `.`

## CI Pipeline Requirements

All PRs must pass these GitHub Actions workflows:

1. **lint.yml** - Runs `make -C constraint lint` (golangci-lint v1.64.8)
2. **workflow.yml** - Runs `make -C constraint native-test` (unit tests)
3. **gatekeeper.yml** - Tests compatibility with Gatekeeper (informative only)

### Linter Rules (from .golangci.yaml)
Active linters: errcheck, copyloopvar, forcetypeassert, goconst, gocritic, godot, gofmt, gofumpt, goimports, gosec, gosimple, govet, ineffassign, misspell, nilerr, revive, staticcheck, unused, whitespace

**Key requirements:**
- Comments must end with a period (godot)
- Files must be properly formatted (gofmt, gofumpt)
- Imports must be properly grouped (goimports)
- No trailing whitespace, files must end with newline

## Code Patterns

### Adding Tests
- Use table-driven tests with `t.Run()` subtest pattern
- Use `github.com/google/go-cmp/cmp` for struct comparisons
- Use `github.com/onsi/gomega` for assertions in some tests
- Tests requiring Kubernetes APIs use envtest (setup via `make native-test`)

### API Changes
1. Modify types in `pkg/apis/templates/` or `pkg/apis/externaldata/`
2. Run `make manifests` to regenerate CRDs
3. Run `make generate-defaults` if adding defaulting logic

### Client Usage Pattern
```go
driver := rego.New()
client, err := client.NewClient(client.Targets(targetHandler), client.Driver(driver))
// Use client.AddTemplate(), client.AddConstraint(), client.Review()
```

## Key Files for Common Tasks

| Task | Primary Files |
|------|---------------|
| Client API | `pkg/client/client.go`, `pkg/client/new_client.go` |
| Review options | `pkg/client/reviews/review_opts.go` |
| Rego driver | `pkg/client/drivers/rego/driver.go` |
| ConstraintTemplate API | `pkg/apis/templates/v1/types.go` |
| Target handler interface | `pkg/handler/handler.go` |
| Result types | `pkg/types/result.go`, `pkg/types/responses.go` |

## Testing

```bash
# Run all tests
make native-test

# Run specific package tests
go test -mod vendor ./pkg/client/... -v

# Run specific test
go test -mod vendor ./pkg/client/... -run TestClient_Review -v
```

Trust these instructions completely for build and test operations. Only search for additional information if specific commands fail or if working on areas not covered above.
