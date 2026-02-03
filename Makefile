.PHONY: all build release release-uefi debug test test-uefi integration coverage clean help

# Default target
all: build

# Build the project
build:
	cargo build

# Build release version
release: release-uefi

release-uefi:
	cargo build --release --target x86_64-unknown-uefi

# Build debug version
debug:
	cargo build

# Run tests (UEFI target)
test: test-uefi

test-uefi:
	cargo test --target x86_64-unknown-uefi

# Run integration scenarios (requires QEMU + OVMF)
integration:
	tools/uefi-integration-assets.sh && \
	tools/uefi-integration-runner.sh memmap && \
	tools/uefi-integration-runner.sh lsefi && \
	tools/uefi-integration-runner.sh mode && \
	tools/uefi-integration-runner.sh rng-seed && \
	tools/uefi-integration-runner.sh fail-timeout && \
	tools/uefi-integration-runner.sh interactive-cmds && \
	tools/uefi-integration-runner.sh kernel-load && \
	tools/uefi-integration-runner.sh secureboot-manifest && \
	tools/uefi-integration-runner.sh secureboot-manifest-bad && \
	tools/uefi-integration-runner.sh kernel-load-modules && \
	tools/uefi-integration-runner.sh kernel-load-iso && \
	tools/uefi-integration-runner.sh zfs-probe && \
	tools/uefi-integration-runner.sh zfs-kernel-load && \
	tools/uefi-integration-runner.sh zfs-passphrase-prompt && \
	tools/uefi-integration-runner.sh zfs-tang-unlock && \
	tools/uefi-integration-runner.sh zfs-bootenvs-real

# Run coverage (no minimum threshold yet)
coverage:
	tools/coverage

# Clean build artifacts
clean:
	cargo clean

# Show help
help:
	@echo "Available targets:"
	@echo "  all          - Build the project (default)"
	@echo "  build        - Build the project"
	@echo "  release      - Build release UEFI loader"
	@echo "  release-uefi - Build release UEFI loader"
	@echo "  debug        - Build debug version"
	@echo "  test         - Run UEFI target tests"
	@echo "  test-uefi    - Run UEFI target tests"
	@echo "  integration - Run integration scenarios"
	@echo "  coverage    - Run coverage without threshold"
	@echo "  clean        - Clean build artifacts"
	@echo "  help         - Show this help message"
