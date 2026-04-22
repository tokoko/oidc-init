# All recipes live in pixi.toml; the Makefile just delegates so users with
# either tool in their muscle memory can use the same target names.

TARGETS := build build-gui build-windows gui run-windows \
           test test-go test-python test-java test-integration \
           lint lint-go lint-python lint-java \
           fmt fmt-go fmt-python \
           setup teardown clean

.PHONY: $(TARGETS)

$(TARGETS):
	@pixi run $@
