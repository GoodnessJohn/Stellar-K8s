# =============================================================================
# Stellar-K8s Makefile
#
# Canonical Command Flow:
#   Setup:    make dev-setup                  # One-time environment setup
#   Check:    make quick                      # Fast pre-commit (fmt check + compile)
#   CI:       make ci-local                   # Full CI pipeline (fmt + lint + audit + test + build + links)
#   Format:   make fmt                        # Auto-format code
#   Build:    make build                      # Release binary build
#   Test:     make test                       # Run all tests
#   Security: make security-all               # Audit + scan
#   Docker:   make docker-build               # Local Docker image
#   Cleanup:  make cleanup                    # Repo scratch + obsolete-path check
#   Clean:    make clean                      # Remove build artifacts
#   Health:   make health                     # Full health check
#   Help:     make help                       # Show all targets
#
# See DEVELOPMENT.md for full workflow details.
# =============================================================================

.PHONY: help \
	fmt fmt-check lint lint-strict shellcheck audit security-scan security-all security-report \
	build test chaos-test ci-local quick watch \
	docker-build docker-build-ci docker-multiarch \
	dev-setup dev-setup-rust dev-setup-tools dev-setup-hooks health-check pre-commit pre-commit-install run run-local run-dev \
	install-crd apply-samples crd-gen regenerate completions completions-bash completions-zsh completions-fish \
	helm-lint helm-unittest helm-upgrade-test link-check link-check-all changelog \
	generate-api-docs check-api-docs generate-openapi-spec check-openapi-spec docs-lint \
	third-party-licenses check-third-party-licenses \
	benchmark benchmark-webhook benchmark-all \
	benchmark-crd benchmark-helm benchmark-api benchmark-reconciliation \
	compose-up compose-dev compose-down compose-logs \
	bundle bundle-render bundle-generate bundle-validate bundle-build \
	quickstart quickstart-setup quickstart-build quickstart-deploy \
	health health-fast validate preflight test-shell all \
	shell-safety test-shell-safety validate-yaml test-yaml-validation \
	yaml-schema-validate test-db-migrations \
	helm-drift helm-drift-update test-helm-drift test-helm-bump \
	collect-failure-diagnostics test-failure-diagnostics \
	check-unreachable-modules \
	check-pipeline-log-redaction \
	license-headers check-license-headers \
	check-api-contract check-api-coverage check-breaking-changes \
	crd-benchmark \
	compliance-test \
	cleanup clean

# Default target
.DEFAULT_GOAL := help

# Variables
CARGO := cargo
KUBECTL := kubectl
DOCKER := docker
IMAGE_NAME := stellar-operator
IMAGE_TAG ?= latest

# Bundle variables
VERSION ?= 0.1.0
BUNDLE_IMG ?= $(IMAGE_NAME)-bundle:v$(VERSION)
CHANNELS ?= "alpha"
DEFAULT_CHANNEL ?= "alpha"

help: ## Show this help
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Canonical Command Flow:'
	@echo '  Setup:    make dev-setup         One-time environment setup'
	@echo '  Check:    make quick             Fast pre-commit (fmt + cargo check)'
	@echo '  CI:       make ci-local          Full CI pipeline locally'
	@echo '  Format:   make fmt               Auto-format code'
	@echo '  Build:    make build              Release binary build'
	@echo '  Test:     make test               Run all tests'
	@echo '  Security: make security-all       Complete security audit suite'
	@echo '  Security: make audit              Vulnerability scan + policy check'
	@echo '  Security: make security-report    Generate security report'
	@echo '  Docker:   make docker-build       Local Docker image'
	@echo '  Cleanup:  make cleanup            Scratch artifacts + obsolete-path check'
	@echo '  Clean:    make clean              Remove build artifacts'
	@echo ''
	@echo 'Workflows:'
	@echo '  make quickstart                  End-to-end local quickstart (kind cluster)'
	@echo '  make health                      Full contributor health gate'
	@echo '  make all                         CI checks + build + Docker image'
	@echo ''
	@echo 'All available targets:'
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_][a-zA-Z0-9_-]+:.*## / {printf "  %-28s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ── Formatting & Linting ──────────────────────────────────────────────────────

fmt: ## Format code
	$(CARGO) fmt --all

fmt-check: ## Check formatting
	@echo "→ Checking format..."
	@$(CARGO) fmt --all --check && echo "✓ Format OK" || (echo "✗ Run: make fmt" && exit 1)

lint: ## Run clippy
	@echo "→ Running clippy..."
	@K8S_OPENAPI_ENABLED_VERSION=1.30 $(CARGO) clippy --workspace --all-targets \
		--features $(CLIPPY_FEATURES) -- \
		$(CLIPPY_BASE_FLAGS)

lint-strict: ## Run clippy (adds complexity checks on top of lint; same base exceptions)
	@echo "→ Running clippy (strict mode)..."
	@K8S_OPENAPI_ENABLED_VERSION=1.30 $(CARGO) clippy --workspace --all-targets \
		--features $(CLIPPY_FEATURES) -- \
		$(CLIPPY_BASE_FLAGS) \
		$(CLIPPY_STRICT_FLAGS)

# ── Security ──────────────────────────────────────────────────────────────────

audit: ## Security audit (cargo audit + deny) via consolidated lockfile gate
	@bash scripts/dep-gate.sh

security-scan: ## Run security scan (audit + dependency policy + shellcheck + shell safety)
	@echo "→ Running comprehensive security scan..."
	$(MAKE) audit
	$(MAKE) shellcheck
	$(MAKE) shell-safety
	@echo "  Checking for outdated dependencies..."
	@command -v cargo-outdated >/dev/null 2>&1 || cargo install --locked cargo-outdated
	@$(CARGO) outdated --root-deps-only || true

security-all: ## Run all security checks (audit + policy + scan + SBOM)
	@echo "→ Running complete security audit suite..."
	$(MAKE) audit
	$(MAKE) shellcheck
	$(MAKE) shell-safety
	@echo "  Generating Software Bill of Materials..."
	@mkdir -p security/sbom
	@$(CARGO) tree --format "{p} {l}" > security/sbom/dependencies.txt
	@$(CARGO) deny list --format json > security/sbom/licenses.json 2>/dev/null || true
	@echo "  ✅ Security audit complete - SBOM available in security/sbom/"

security-report: ## Generate comprehensive security report  
	@echo "→ Generating security report..."
	@mkdir -p security/reports
	@echo "# Security Report - $(shell date)" > security/reports/security-report.md
	@echo "" >> security/reports/security-report.md
	@echo "## Vulnerability Scan" >> security/reports/security-report.md
	@$(CARGO) audit --format json > security/reports/audit.json 2>/dev/null || true
	@echo "" >> security/reports/security-report.md  
	@echo "## Dependency Policy Check" >> security/reports/security-report.md
	@$(CARGO) deny check --format json > security/reports/deny.json 2>/dev/null || true
	@echo "" >> security/reports/security-report.md
	@echo "## License Compliance" >> security/reports/security-report.md
	@$(CARGO) deny list >> security/reports/security-report.md 2>/dev/null || true
	@echo "  📊 Security report generated in security/reports/"

shellcheck: ## Run shellcheck on all shell scripts
	@echo "→ Running shellcheck..."
	@find scripts -type f -name "*.sh" -print0 | xargs -0 shellcheck -S error || true

compliance-test: ## Validate kube-bench compliance fixtures (CIS custom controls) (#1380)
	@echo "→ Running kube-bench compliance static checks..."
	@bash security/kube-bench/run-local.sh --check-only

shell-safety: ## Static analysis gate for unsafe shell patterns (#1049)
	@python3 scripts/check-shell-safety.py

test-shell-safety: ## Unit tests for the shell safety gate (#1049)
	@echo "→ Testing shell safety gate..."
	@python3 -m unittest scripts.tests.test_check_shell_safety

# ── Manifest validation & drift ───────────────────────────────────────────────

validate-yaml: ## Repository-wide schema validation for YAML manifests (#1044)
	@python3 scripts/validate-yaml-manifests.py

test-yaml-validation: ## Unit tests for the YAML manifest validator (#1044)
	@echo "→ Testing YAML manifest validator..."
	@python3 -m unittest scripts.tests.test_validate_yaml_manifests

yaml-schema-validate: ## yamllint + CRD schema drift + Helm-render kubeconform (#1291)
	@echo "→ Running YAML / CRD / Helm schema validation..."
	@bash scripts/ci/validate-yaml.sh

test-db-migrations: ## Forward/rollback SQL migration harness (#1317)
	@echo "→ Running database migration tests..."
	@bash scripts/ci/test-db-migrations.sh

helm-drift: ## Detect drift between Helm templates and the committed renders (#1045)
	@bash scripts/check-helm-drift.sh

helm-drift-update: ## Regenerate the committed Helm render goldens (#1045)
	@bash scripts/check-helm-drift.sh --update

test-helm-drift: ## Bats tests for the Helm drift gate (#1045)
	@echo "→ Testing Helm drift gate..."
	@command -v bats >/dev/null 2>&1 || (echo "✗ bats not installed. See https://github.com/bats-core/bats-core" && exit 1)
	@bats scripts/tests/helm-drift.bats

test-helm-bump: ## Bats tests for bump-chart-version.sh (#1319)
	@echo "→ Testing chart version bump script..."
	@command -v bats >/dev/null 2>&1 || (echo "✗ bats not installed. See https://github.com/bats-core/bats-core" && exit 1)
	@bats scripts/tests/bump-chart-version.bats

# ── Test & Build ──────────────────────────────────────────────────────────────

test: ## Run tests
	@echo "→ Running tests..."
	@$(CARGO) test --workspace --features "rest-api,metrics,admission-webhook,k8s-v1-30,reconciler-fuzz" --tests --lib --bins --verbose
	@echo "→ Running doc tests..."
	@$(CARGO) test --doc --workspace --features "rest-api,metrics,admission-webhook,k8s-v1-30"

build: ## Build release
	@echo "→ Building release..."
	@$(CARGO) build --release --locked

chaos-test: ## Run the chaos engineering resilience suite (needs kind + Chaos Mesh)
	@echo "→ Running chaos engineering test suite..."
	@bash tests/chaos/run-chaos-tests.sh

# ── Docker ────────────────────────────────────────────────────────────────────

docker-build: ## Fast local Docker build using host release binaries
	@echo "→ Building Docker image (fast local mode)..."
	@if [ ! -f target/release/stellar-operator ] || [ ! -f target/release/kubectl-stellar ] || [ ! -f target/release/soroban-cache-proxy ]; then \
		echo "→ Release binaries not found, building once..."; \
		$(MAKE) build; \
	fi
	DOCKER_BUILDKIT=1 $(DOCKER) build --target runtime-local -t $(IMAGE_NAME):$(IMAGE_TAG) .

docker-build-ci: ## Reproducible CI Docker build (builds binaries in container)
	@echo "→ Building Docker image (CI mode)..."
	DOCKER_BUILDKIT=1 $(DOCKER) build --target runtime -t $(IMAGE_NAME):$(IMAGE_TAG) .

docker-multiarch: ## Build the multi-arch (linux/amd64 + linux/arm64) image locally via buildx
	@echo "→ Building multi-arch image for linux/amd64,linux/arm64..."
	@$(DOCKER) buildx version >/dev/null 2>&1 || { \
		echo "✗ docker buildx not available. Install the buildx builder plugin."; \
		exit 1; \
	}
	DOCKER_BUILDKIT=1 $(DOCKER) buildx build \
		--platform linux/amd64,linux/arm64 \
		--target runtime-local \
		-t $(IMAGE_NAME):$(IMAGE_TAG) .

# CI publishes the multi-arch image from the `container` job in
# .github/workflows/release.yml (QEMU + buildx) on tagged releases. The
# `make docker-multiarch` target above is the local equivalent.

health: ## Run common repository health checks (format, lint, test, docs, links)
	@bash scripts/repo-health.sh

health-fast: ## Fast health gate (format, lint, compile only)
	@bash scripts/repo-health.sh --fast

validate: health-fast ## Fast validation (alias for health-fast)

# ── Quality & Health ───────────────────────────────────────────────────────────

check-unreachable-modules: ## Static check for unreachable modules and dead code paths (#1150)
	@echo "→ Checking unreachable modules and dead code paths..."
	@$(CARGO) run --quiet --locked --bin check-unreachable-modules

ci-local: fmt-check lint audit test build ## Run full CI locally
	@echo ""
	@echo "✓ All CI checks passed!"

quick: fmt-check ## Quick pre-commit check
	@$(CARGO) check --workspace
	@echo "✓ Quick checks passed"

pre-commit: ## Run pre-commit hooks manually
	@echo "→ Running pre-commit hooks..."
	@command -v pre-commit >/dev/null 2>&1 || (echo "✗ pre-commit not installed. Run: make dev-setup" && exit 1)
	@pre-commit run --all-files

pre-commit-install: dev-setup-hooks ## Install pre-commit hooks (alias for dev-setup-hooks)
	@echo "✓ pre-commit hooks installed"

clean: ## Clean build artifacts
	$(CARGO) clean

generate-api-docs: ## Generate API reference docs from CRD schema
	@echo "→ Generating API reference docs..."
	@python3 scripts/generate-api-docs.py \
		--crd config/crd/stellarnode-crd.yaml \
		--output docs/api-reference.md
	@echo "✓ Generated docs/api-reference.md"

check-api-docs: ## Check API docs are up to date (used in CI)
	@echo "→ Checking API reference docs are up to date..."
	@python3 scripts/generate-api-docs.py \
		--crd config/crd/stellarnode-crd.yaml \
		--output docs/api-reference.md \
		--check

generate-openapi-spec: ## Validate operator REST OpenAPI specification
	@echo "→ Validating OpenAPI specification..."
	@python3 scripts/generate-openapi-spec.py --spec docs/api/openapi.yaml
	@echo "✓ docs/api/openapi.yaml is valid"

docs-lint: ## Run rustdoc with warnings-as-errors (issue #1138: strict docs quality gate)
	@echo "→ Running cargo doc with RUSTDOCFLAGS=-D warnings..."
	@RUSTDOCFLAGS="-D warnings" K8S_OPENAPI_ENABLED_VERSION=1.30 \
		$(CARGO) doc --no-deps --workspace \
		--features "rest-api,metrics,admission-webhook,k8s-v1-30"
	@echo "✓ rustdoc passed — no documentation warnings"

check-openapi-spec: ## Fail if OpenAPI spec is missing required operator routes
	@echo "→ Checking OpenAPI spec coverage..."
	@python3 scripts/generate-openapi-spec.py --spec docs/api/openapi.yaml --check

# ── Kubernetes ────────────────────────────────────────────────────────────────

install-crd: ## Install CRDs
	$(KUBECTL) apply -f config/crd/stellarnode-crd.yaml

apply-samples: install-crd ## Apply samples
	$(KUBECTL) apply -f config/samples/

crd-gen: ## Generate CRDs
	@echo "→ Generating CRDs..."
	@$(CARGO) run --bin crdgen | python3 scripts/sort-manifests.py > config/crd/stellarnode-crd.yaml
	@echo "✓ CRD written to config/crd/stellarnode-crd.yaml (deterministic order)"

regenerate: crd-gen generate-api-docs bundle ## Regenerate all derived artifacts (CRDs, API docs, OLM bundle)
	@echo "✓ All generated artifacts are up to date"
	@echo "  See docs/development/regeneration-guide.md for details"

preflight: ## Check that required tools are installed (pass --labels to also verify repo labels)
	@bash scripts/preflight.sh $(ARGS)

test-shell: ## Run bats unit tests for the cleanup tool and shared shell helpers
	@echo "→ Running cleanup tool bats tests..."
	@command -v bats >/dev/null 2>&1 || (echo "✗ bats not installed. See https://github.com/bats-core/bats-core" && exit 1)
	@bats scripts/tests/cleanup.bats

collect-failure-diagnostics: ## Assemble a local CI failure diagnostics bundle (#1151)
	@echo "→ Assembling failure diagnostics bundle..."
	@chmod +x scripts/ci/collect-failure-diagnostics.sh
	@./scripts/ci/collect-failure-diagnostics.sh --no-cluster \
		--bundle-dir "$${BUNDLE_DIR:-/tmp/ci-diagnostics}" \
		--job-name "$${JOB_NAME:-local}"

test-failure-diagnostics: ## Verify the unified diagnostics collector (#1151)
	@echo "→ Testing failure diagnostics collector..."
	@command -v bats >/dev/null 2>&1 || (echo "✗ bats not installed. See https://github.com/bats-core/bats-core" && exit 1)
	@bats scripts/tests/failure-diagnostics.bats

check-pipeline-log-redaction: ## Enforce secret redaction on pipeline command logs (#1153)
	@echo "→ Checking pipeline log secret redaction..."
	@$(CARGO) run --quiet --locked --bin check-pipeline-log-redaction -- \
		--fixture tests/fixtures/pipeline_logs/dirty-ci-sample.txt

# ── Issue #1286: License header enforcement ───────────────────────────────────

license-headers: ## Check license headers on Rust/Shell/YAML files (#1286)
	@echo "→ Checking license headers..."
	@python3 scripts/check-license-headers.py

check-license-headers: license-headers ## Alias for license-headers

# ── Issue #1287: CRD performance regression ───────────────────────────────────

crd-benchmark: ## Build CRD operation benchmarks (#1287)
	@echo "→ Building CRD benchmarks..."
	@$(CARGO) bench --bench crd_operations --no-run
	@echo "✓ CRD benchmarks compiled (run with: cargo bench --bench crd_operations)"

# ── Issue #1288: API contract testing ─────────────────────────────────────────

check-api-contract: ## Validate API contract against OpenAPI spec (#1288)
	@echo "→ Validating API contract..."
	@python3 scripts/check-api-contract.py check --spec docs/api/openapi.yaml

check-api-coverage: ## Check API endpoint coverage exceeds 90% (#1288)
	@echo "→ Checking API endpoint coverage..."
	@python3 scripts/check-api-contract.py coverage --spec docs/api/openapi.yaml --min-coverage 90

check-breaking-changes: ## Detect breaking API changes vs base branch (#1288)
	@echo "→ Detecting breaking API changes..."
	@python3 scripts/check-api-contract.py breaking \
		--base /tmp/base-openapi.yaml \
		--head docs/api/openapi.yaml

completions: ## Generate shell completion scripts
	@echo "→ Generating shell completions..."
	@mkdir -p completions
	@$(CARGO) run --bin stellar-completions completions bash > completions/stellar-operator.bash
	@$(CARGO) run --bin stellar-completions completions zsh > completions/_stellar-operator
	@$(CARGO) run --bin stellar-completions completions fish > completions/stellar-operator.fish
	@echo "✓ Completions generated in ./completions/"
	@echo "  Bash: source completions/stellar-operator.bash"
	@echo "  Zsh:  Copy completions/_stellar-operator to your fpath"
	@echo "  Fish: Copy completions/stellar-operator.fish to ~/.config/fish/completions/"

helm-lint: ## Helm lint check
	@echo "→ Linting Helm charts..."
	helm lint charts/stellar-operator

dev-setup: ## Setup dev environment
	rustup update stable
	rustup default stable
	rustup component add clippy rustfmt
	cargo install cargo-audit cargo-watch
	@command -v pre-commit >/dev/null 2>&1 || pip install pre-commit
	pre-commit install
	pre-commit install --hook-type pre-push

watch: ## Watch and rebuild
	cargo watch -x check -x test -x build

benchmark: ## Run k6 performance benchmarks
	@echo "→ Running k6 benchmarks..."
	@command -v k6 >/dev/null 2>&1 || (echo "✗ k6 not installed. Install: https://k6.io/docs/get-started/installation/" && exit 1)
	cd benchmarks && k6 run k6/operator-load-test.js

benchmark-webhook: ## Run webhook performance benchmarks
	@echo "→ Running webhook benchmarks..."
	@command -v k6 >/dev/null 2>&1 || (echo "✗ k6 not installed. Install: https://k6.io/docs/get-started/installation/" && exit 1)
	@./benchmarks/run-webhook-benchmark.sh run

benchmark-webhook-health: ## Check webhook health
	@./benchmarks/run-webhook-benchmark.sh health

benchmark-webhook-compare: ## Compare webhook results with baseline
	@./benchmarks/run-webhook-benchmark.sh compare

benchmark-webhook-save: ## Save current results as baseline
	@./benchmarks/run-webhook-benchmark.sh save-baseline

benchmark-all: benchmark benchmark-webhook ## Run all benchmarks

# ── Running the Operator ──────────────────────────────────────────────────────

run-local: build ## Run operator locally from built release binary
	RUST_LOG=info ./target/release/stellar-operator run

run: run-local ## Run the operator (alias for run-local; matches README and CI references)

run-dev: ## Run operator in dev mode with hot reload
	RUST_LOG=debug cargo watch -x run

# Bundle targets
.PHONY: bundle bundle-build
bundle: ## Generate bundle manifests and metadata, then validate generated files.
	@echo "→ Generating manifests from Helm chart..."
	@mkdir -p rendered
	@helm template stellar-operator charts/stellar-operator > rendered/manifests.yaml
	@echo "→ Generating bundle..."
	@operator-sdk generate kustomize manifests -q
	@kustomize build config/manifests | operator-sdk generate bundle -q --overwrite --version $(VERSION) --channels $(CHANNELS) --default-channel $(DEFAULT_CHANNEL)
	@echo "→ Validating bundle..."
	@operator-sdk bundle validate ./bundle
	@rm -rf rendered

bundle-build: ## Build the bundle image.
	docker build -f bundle.Dockerfile -t $(BUNDLE_IMG) .

quickstart: ## End-to-end local quickstart: kind cluster + CRD + operator + sample StellarNode
	@echo "→ Checking prerequisites..."
	@command -v kind >/dev/null 2>&1 || (echo "✗ kind not found. Install: https://kind.sigs.k8s.io/docs/user/quick-start/#installation" && exit 1)
	@command -v kubectl >/dev/null 2>&1 || (echo "✗ kubectl not found. Install: https://kubernetes.io/docs/tasks/tools/" && exit 1)
	@command -v helm >/dev/null 2>&1 || (echo "✗ helm not found. Install: https://helm.sh/docs/intro/install/" && exit 1)
	@echo "→ Creating kind cluster 'stellar-dev'..."
	@kind create cluster --name stellar-dev --wait 120s || echo "  (cluster may already exist, continuing)"
	@echo "→ Building operator image..."
	@$(MAKE) build
	@DOCKER_BUILDKIT=1 $(DOCKER) build --target runtime-local -t stellar-operator:dev .
	@echo "→ Loading image into kind cluster..."
	@kind load docker-image stellar-operator:dev --name stellar-dev
	@echo "→ Installing CRD..."
	@$(KUBECTL) apply -f config/crd/stellarnode-crd.yaml
	@echo "→ Creating namespace stellar-system..."
	@$(KUBECTL) create namespace stellar-system --dry-run=client -o yaml | $(KUBECTL) apply -f -
	@echo "→ Deploying operator via Helm..."
	@helm upgrade --install stellar-operator charts/stellar-operator \
		--namespace stellar-system \
		--set image.tag=dev \
		--set image.pullPolicy=Never \
		--wait --timeout 120s
	@echo "→ Applying sample StellarNode..."
	@$(KUBECTL) apply -f config/samples/test-stellarnode.yaml
	@echo ""
	@echo "✓ Quickstart complete!"
	@echo "  Watch nodes:    kubectl get stellarnode -n stellar-system -w"
	@echo "  View resources: kubectl get deploy,sts,svc,pvc -n stellar-system"
	@echo "  Cleanup:        kind delete cluster --name stellar-dev"

all: ci-local docker-build ## Full build pipeline

# Docker Compose targets
compose-up: ## Start Docker Compose development environment
	@echo "→ Starting Docker Compose environment..."
	@docker-compose up -d
	@echo "✓ Environment started. Use 'make compose-logs' to view logs"

compose-dev: ## Start Docker Compose with hot-reloading
	@echo "→ Starting Docker Compose with hot-reloading..."
	@docker-compose -f docker-compose.yml -f docker-compose.dev.yml up

compose-down: ## Stop Docker Compose environment
	@echo "→ Stopping Docker Compose environment..."
	@docker-compose down

compose-logs: ## View Docker Compose logs
	@docker-compose logs -f stellar-operator
