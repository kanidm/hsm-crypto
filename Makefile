GIT_COMMIT := $(shell git rev-parse HEAD)
TESTS :=

.DEFAULT: help
.PHONY: help
help:
	@grep -E -h '\s##\s' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: test
test:
	cargo test

.PHONY: precommit
precommit: ## all the usual test things
precommit: test codespell doc/format

.PHONY: codespell
codespell: ## spell-check things.
codespell:
	codespell -c \
	-L 'crate,unexpect,Pres,pres,ACI,aci,ser,te,ue,unx,aNULL' \
	--skip='./target'

.PHONY: doc
doc: ## Build the rust documentation locally
doc:
	cargo doc --document-private-items

.PHONY: doc/format
doc/format: ## Format docs and the Kanidm book
	find . -type f  -not -path './target/*' -not -path '*/.venv/*' \
		-name \*.md \
		-exec deno fmt --check $(MARKDOWN_FORMAT_ARGS) "{}" +

.PHONY: doc/format/fix
doc/format/fix: ## Fix docs and the Kanidm book
	find . -type f  -not -path './target/*' -not -path '*/.venv/*' \
		-name \*.md \
		-exec deno fmt  $(MARKDOWN_FORMAT_ARGS) "{}" +

.PHONY: release/prep
release/prep:
	cargo outdated -R
	cargo audit

.PHONY: rust/coverage
coverage/test: ## Run coverage tests
coverage/test:
	LLVM_PROFILE_FILE="$(PWD)/target/profile/coverage-%p-%m.profraw" RUSTFLAGS="-C instrument-coverage" cargo test $(TESTS)

.PHONY: coverage/grcov
coverage/grcov: ## Run grcov
coverage/grcov:
	rm -rf ./target/coverage/html
	grcov . --binary-path ./target/debug/deps/ \
		-s . \
		-t html \
		--branch \
		--ignore-not-existing \
		--ignore '../*' \
		--ignore "/*" \
		--ignore "target/*" \
		-o target/coverage/html

.PHONY: coverage
coverage: ## Run all the coverage tests
coverage: coverage/test coverage/grcov
	echo "Coverage report is in ./target/coverage/html/index.html"
