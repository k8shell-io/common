PROTO_DIR   := pkg/api/proto
GEN_DIR     := pkg/api/gen/go
PROTO_FILES := $(shell find $(PROTO_DIR) -name '*.proto')

# Use buf if available, otherwise fall back to protoc.
.PHONY: proto
proto:
	@if command -v buf > /dev/null 2>&1; then \
		echo "Generating with buf..."; \
		cd $(PROTO_DIR) && buf generate; \
	else \
		echo "buf not found, generating with protoc..."; \
		rm -rf $(GEN_DIR); \
		mkdir -p $(GEN_DIR); \
		protoc \
			--proto_path=$(PROTO_DIR) \
			--proto_path=/usr/include \
			--experimental_allow_proto3_optional \
			--go_out=$(GEN_DIR) \
			--go_opt=paths=source_relative \
			$(PROTO_FILES); \
		protoc \
			--proto_path=$(PROTO_DIR) \
			--proto_path=/usr/include \
			--experimental_allow_proto3_optional \
			--go_out=$(GEN_DIR) \
			--go_opt=paths=source_relative \
			--go-grpc_out=$(GEN_DIR) \
			--go-grpc_opt=paths=source_relative \
			$(shell find $(PROTO_DIR) -name '*.proto' | xargs grep -l 'service '); \
	fi

.PHONY: proto-lint
proto-lint:
	@cd $(PROTO_DIR) && buf lint

.PHONY: proto-breaking
proto-breaking:
	@cd $(PROTO_DIR) && buf breaking --against '.git#branch=main'
