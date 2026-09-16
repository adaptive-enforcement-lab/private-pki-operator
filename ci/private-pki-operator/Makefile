REGISTRY ?= ghcr.io/adaptive-enforcement-lab
TAG      ?= dev

# Image URL to use all building/pushing image targets
IMG ?= $(REGISTRY)/private-pki-operator:$(TAG)

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# CONTAINER_TOOL defines the container tool to be used for building images.
# Be aware that the target commands are only tested with Docker which is
# scaffolded by default. However, you might want to replace it to use other
# tools. (i.e. podman)
CONTAINER_TOOL ?= docker

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	"$(CONTROLLER_GEN)" rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases
	@for crd in pkirotations; do \
	  src="config/crd/bases/platform.adaptive-enforcement-lab.com_$${crd}.yaml"; \
	  dst="../../charts/private-pki-operator/templates/crds/$${crd}.yaml"; \
	  printf '{{- if .Values.installCRDs }}\n' > "$$dst"; \
	  cat "$$src" >> "$$dst"; \
	  printf '{{- end }}\n' >> "$$dst"; \
	done

# `generate` depends on `manifests` so that one target regenerates every artefact
# derived from api/. Left independent, a contributor who adds a field to an API type
# and runs only `manifests` ships a CRD schema that accepts the field and a
# zz_generated.deepcopy.go that does not copy it — DeepCopy() then returns objects
# sharing a pointer, slice or map with the informer cache. Other operator
# Makefiles are shaped the same way for the same reason.
.PHONY: generate
generate: manifests ## Generate everything: CRDs, the synced chart templates, RBAC and DeepCopy methods.
	"$(CONTROLLER_GEN)" object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: manifests generate fmt vet setup-envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell "$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path)" go test $$(go list ./... | grep -v /e2e) -coverprofile cover.out

# TODO(user): To use a different vendor for e2e tests, modify the setup under 'tests/e2e'.
# The default setup assumes Kind is pre-installed and builds/loads the Manager Docker image locally.
# CertManager is installed by default; skip with:
# - CERT_MANAGER_INSTALL_SKIP=true
KIND_CLUSTER ?= private-pki-operator-test-e2e

.PHONY: setup-test-e2e
setup-test-e2e: ## Set up a Kind cluster for e2e tests if it does not exist
	@command -v $(KIND) >/dev/null 2>&1 || { \
		echo "Kind is not installed. Please install Kind manually."; \
		exit 1; \
	}
	@case "$$($(KIND) get clusters)" in \
		*"$(KIND_CLUSTER)"*) \
			echo "Kind cluster '$(KIND_CLUSTER)' already exists. Skipping creation." ;; \
		*) \
			echo "Creating Kind cluster '$(KIND_CLUSTER)'..."; \
			$(KIND) create cluster --name $(KIND_CLUSTER) ;; \
	esac

.PHONY: test-e2e
test-e2e: setup-test-e2e manifests generate fmt vet ## Run the e2e tests. Expected an isolated environment using Kind.
	KIND=$(KIND) KIND_CLUSTER=$(KIND_CLUSTER) go test -tags=e2e ./test/e2e/ -v -ginkgo.v
	$(MAKE) cleanup-test-e2e

.PHONY: cleanup-test-e2e
cleanup-test-e2e: ## Tear down the Kind cluster used for e2e tests
	@$(KIND) delete cluster --name $(KIND_CLUSTER)

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter
	"$(GOLANGCI_LINT)" run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	"$(GOLANGCI_LINT)" run --fix

.PHONY: lint-config
lint-config: golangci-lint ## Verify golangci-lint linter configuration
	"$(GOLANGCI_LINT)" config verify

##@ Build

.PHONY: build
build: manifests generate fmt vet ## Build manager binary.
	go build -o bin/manager cmd/main.go

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	go run ./cmd/main.go

# If you wish to build the manager image targeting other platforms you can use the --platform flag.
# (i.e. docker build --platform linux/arm64). However, you must enable docker buildKit for it.
# More info: https://docs.docker.com/develop/develop-images/build_enhancements/
.PHONY: docker-build
docker-build: ## Build docker image with the manager (linux/amd64).
	$(CONTAINER_TOOL) build --platform linux/amd64 -t ${IMG} .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	$(CONTAINER_TOOL) push ${IMG}

.PHONY: build-push
build-push: docker-build docker-push ## Build and push docker image (linux/amd64).

# PLATFORMS defines the target platforms for the manager image be built to provide support to multiple
# architectures. (i.e. make docker-buildx IMG=myregistry/mypoperator:0.0.1). To use this option you need to:
# - be able to use docker buildx. More info: https://docs.docker.com/build/buildx/
# - have enabled BuildKit. More info: https://docs.docker.com/develop/develop-images/build_enhancements/
# - be able to push the image to your registry (i.e. if you do not set a valid value via IMG=<myregistry/image:<tag>> then the export will fail)
# To adequately provide solutions that are compatible with multiple platforms, you should consider using this option.
PLATFORMS ?= linux/arm64,linux/amd64,linux/s390x,linux/ppc64le
.PHONY: docker-buildx
docker-buildx: ## Build and push docker image for the manager for cross-platform support
	# copy existing Dockerfile and insert --platform=${BUILDPLATFORM} into Dockerfile.cross, and preserve the original Dockerfile
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > Dockerfile.cross
	- $(CONTAINER_TOOL) buildx create --name private-pki-operator-builder
	$(CONTAINER_TOOL) buildx use private-pki-operator-builder
	- $(CONTAINER_TOOL) buildx build --push --platform=$(PLATFORMS) --tag ${IMG} -f Dockerfile.cross .
	- $(CONTAINER_TOOL) buildx rm private-pki-operator-builder
	rm Dockerfile.cross

##@ Functional Testing

# Chart path and cluster resource names (relative to ci/private-pki-operator/)
CHART         ?= ../../charts/private-pki-operator
PKI_NAMESPACE ?= cert-manager
ROOT_SECRET   ?= private-root-ca
PKIR_NAME     ?= platform-root-ca

# Intermediate CA Certificate name (must match the cert-manager Certificate resource)
INTERMEDIATE_CERT ?= private-intermediate-ca

.PHONY: trigger-rotation
trigger-rotation: ## Trigger a root CA rotation by deleting the root CA Secret (cert-manager reissues root with a new key, which triggers the operator state machine)
	@printf "=== Deleting Secret/%s in namespace %s ===\n" "$(ROOT_SECRET)" "$(PKI_NAMESPACE)"
	$(KUBECTL) delete secret $(ROOT_SECRET) -n $(PKI_NAMESPACE)
	@printf "=== Watching operator logs for phase transitions (Ctrl-C when done) ===\n"
	$(KUBECTL) logs -n $(PKI_NAMESPACE) deployment/private-pki-operator -c manager -f

.PHONY: watch-rotation
watch-rotation: ## Stream operator logs showing phase transitions
	$(KUBECTL) logs -n $(PKI_NAMESPACE) deployment/private-pki-operator -c manager --tail=20 -f

.PHONY: rotation-status
rotation-status: ## Show current PKIRotation phase and conditions
	$(KUBECTL) get pkirotation $(PKIR_NAME) -o jsonpath='{.status}' | python3 -m json.tool 2>/dev/null \
	  || $(KUBECTL) get pkirotation $(PKIR_NAME) -o yaml | grep -A 40 "^status:"

.PHONY: verify-trust
verify-trust: ## Verify trust-manager has distributed the root CA to all namespaces
	@printf "=== Bundle / private-root-ca conditions ===\n"
	$(KUBECTL) get bundle private-root-ca \
	  -o jsonpath='{range .status.conditions[*]}{.type}: {.status}\n{end}'
	@printf "\n=== Root CA cert in namespace $(PKI_NAMESPACE) ===\n"
	$(KUBECTL) get configmap private-root-ca -n $(PKI_NAMESPACE) \
	  -o jsonpath='{.data.ca\.crt}' \
	  | openssl x509 -noout -subject -issuer -enddate

.PHONY: test-reissuance-trigger
test-reissuance-trigger: ## Test the Issuing-condition reissuance mechanism in isolation (replicates what the operator does; does NOT trigger a full rotation)
	@printf "=== Reading current generation of Certificate/%s ===\n" "$(INTERMEDIATE_CERT)"
	@GEN=$$($(KUBECTL) get certificate $(INTERMEDIATE_CERT) -n $(PKI_NAMESPACE) -o jsonpath='{.metadata.generation}'); \
	NOW=$$(date -u +%Y-%m-%dT%H:%M:%SZ); \
	printf "Patching Certificate/%s status: Issuing=True (generation=%s)\n" "$(INTERMEDIATE_CERT)" "$$GEN"; \
	$(KUBECTL) patch certificate $(INTERMEDIATE_CERT) -n $(PKI_NAMESPACE) \
	  --subresource=status --type=merge \
	  -p "{\"status\":{\"conditions\":[{\"type\":\"Issuing\",\"status\":\"True\",\"reason\":\"ManuallyTriggered\",\"message\":\"Reissuance mechanism test\",\"observedGeneration\":$$GEN,\"lastTransitionTime\":\"$$NOW\"}]}}"
	@printf "\n=== Watching for new CertificateRequest (should appear within ~5s, Ctrl-C when done) ===\n"
	$(KUBECTL) get certificaterequest -n $(PKI_NAMESPACE) -w

HARNESS_DIR := hack/test-harness

.PHONY: test-harness
test-harness: ## Run full Nushell in-cluster test harness (DESTRUCTIVE: triggers root rotations)
	cd $(CURDIR) && nu $(HARNESS_DIR)/run.nu

.PHONY: test-harness-verify
test-harness-verify: ## Verify cluster baseline state (non-destructive)
	cd $(CURDIR) && nu $(HARNESS_DIR)/run.nu --scenario 0

.PHONY: test-harness-intermediate
test-harness-intermediate: ## Run independent intermediate cascade scenario (deletes one intermediate Secret)
	cd $(CURDIR) && nu $(HARNESS_DIR)/run.nu --scenario 2

.PHONY: test-harness-interlock
test-harness-interlock: ## Run root + intermediate interlock scenario (triggers root rotation)
	cd $(CURDIR) && nu $(HARNESS_DIR)/run.nu --scenario 3

.PHONY: verify-no-secret-delete
verify-no-secret-delete: ## Verify the deployed operator Role does not grant secrets:delete (RBAC regression check)
	@printf "=== Checking operator Role for secrets:delete ===\n"
	@if $(KUBECTL) get role private-pki-operator -n $(PKI_NAMESPACE) \
	    -o jsonpath='{.rules}' 2>/dev/null | grep -q '"delete"'; then \
	  printf "FAIL: secrets:delete found in operator Role — regression detected\n"; exit 1; \
	else \
	  printf "PASS: operator Role does not grant secrets:delete\n"; \
	fi

##@ Deployment
#
# No default VALUES file here on purpose — the consuming cluster's repo owns
# its own override values (e.g. homelab's k8s/private-pki-operator/values.yaml),
# not this repo. Pass VALUES= explicitly.

OPERATOR_NS ?= cert-manager

.PHONY: deploy
deploy: ## Apply operator chart via Helm template (image must be pre-built with build-push). Usage: make deploy VALUES=<path>
	helm template private-pki-operator $(CHART) \
	  --namespace $(OPERATOR_NS) \
	  -f $(VALUES) \
	  --set image.tag=$(TAG) \
	  | $(KUBECTL) apply -f -
	$(KUBECTL) rollout status deployment/private-pki-operator -n $(OPERATOR_NS)

.PHONY: undeploy
undeploy: ## Remove the operator chart via Helm template. Usage: make undeploy VALUES=<path>
	helm template private-pki-operator $(CHART) \
	  --namespace $(OPERATOR_NS) \
	  -f $(VALUES) \
	  --set image.tag=$(TAG) \
	  | $(KUBECTL) delete --ignore-not-found -f -

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p "$(LOCALBIN)"

## Tool Binaries
## No default context — pass KUBECTL explicitly (e.g.
## KUBECTL='kubectl --kubeconfig ~/.kube/homelab.yaml --context homelab') or
## export it in your shell. An unset default here is deliberate: a wrong
## silent default risks targeting the wrong cluster.
KUBECTL ?= kubectl
KIND ?= kind
KUSTOMIZE ?= $(LOCALBIN)/kustomize
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint

## Tool Versions
KUSTOMIZE_VERSION ?= v5.8.1
CONTROLLER_TOOLS_VERSION ?= v0.20.1

#ENVTEST_VERSION is the version of controller-runtime release branch to fetch the envtest setup script (i.e. release-0.20)
ENVTEST_VERSION ?= $(shell v='$(call gomodver,sigs.k8s.io/controller-runtime)'; \
  [ -n "$$v" ] || { echo "Set ENVTEST_VERSION manually (controller-runtime replace has no tag)" >&2; exit 1; }; \
  printf '%s\n' "$$v" | sed -E 's/^v?([0-9]+)\.([0-9]+).*/release-\1.\2/')

#ENVTEST_K8S_VERSION is the version of Kubernetes to use for setting up ENVTEST binaries (i.e. 1.31)
ENVTEST_K8S_VERSION ?= $(shell v='$(call gomodver,k8s.io/api)'; \
  [ -n "$$v" ] || { echo "Set ENVTEST_K8S_VERSION manually (k8s.io/api replace has no tag)" >&2; exit 1; }; \
  printf '%s\n' "$$v" | sed -E 's/^v?[0-9]+\.([0-9]+).*/1.\1/')

# Pinned explicitly for `make lint` and the pre-commit hook (same binary,
# same version, both local — CI does not currently run golangci-lint).
GOLANGCI_LINT_VERSION ?= v2.13.2
.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary.
$(KUSTOMIZE): $(LOCALBIN)
	$(call go-install-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v5,$(KUSTOMIZE_VERSION))

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

.PHONY: setup-envtest
setup-envtest: envtest ## Download the binaries required for ENVTEST in the local bin directory.
	@echo "Setting up envtest binaries for Kubernetes version $(ENVTEST_K8S_VERSION)..."
	@"$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path || { \
		echo "Error: Failed to set up envtest binaries for version $(ENVTEST_K8S_VERSION)."; \
		exit 1; \
	}

.PHONY: envtest
envtest: $(ENVTEST) ## Download setup-envtest locally if necessary.
$(ENVTEST): $(LOCALBIN)
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest,$(ENVTEST_VERSION))

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))
	@# THE CUSTOM-BINARY BUILD IS GONE, with .custom-gcl.yml.
	@# It existed to compile in two MODULE-PLUGIN
	@# linters, logcheck and kubeapilinter, which only this module's own
	@# .golangci.yml enabled. That config is deleted: the module now inherits the
	@# repository-root golden config, which carries no plugin linters BY DESIGN
	@# because it must run on a STOCK golangci-lint in CI and in pre-commit alike.
	@#
	@# It was not merely dead once the config went — it actively broke CI.
	@# golangci-lint-action@v9 detects a .custom-gcl.yml, spends ~6 minutes
	@# building a custom binary from the version pinned in THAT file, and runs it
	@# in place of the pinned stock binary. The hub's config-resolution assertion
	@# then finds no `golangci-lint` to ask and fails the job outright.
	@#
	@# Issue #274 goes with it: the GIT_DIR/GIT_INDEX_FILE/GIT_WORK_TREE unset
	@# that used to wrap the build existed only because `golangci-lint custom`
	@# shells out to git inside its own source tree and would otherwise write
	@# golangci-lint's files into this repository's index under a git hook. With
	@# no nested build there is nothing left to leak into.

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f "$(1)-$(3)" ] && [ "$$(readlink -- "$(1)" 2>/dev/null)" = "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f "$(1)" ;\
GOBIN="$(LOCALBIN)" go install $${package} ;\
mv "$(LOCALBIN)/$$(basename "$(1)")" "$(1)-$(3)" ;\
} ;\
ln -sf "$$(realpath "$(1)-$(3)")" "$(1)"
endef

define gomodver
$(shell go list -m -f '{{if .Replace}}{{.Replace.Version}}{{else}}{{.Version}}{{end}}' $(1) 2>/dev/null)
endef
