protoc:
	@echo "Generating Go code from proto file..."
	rm -rf pkg/gapi/commonpb
	protoc \
		--go_out=module=github.com/k8shell-io/common:. \
		--go-grpc_out=module=github.com/k8shell-io/common:. \
		pkg/gapi/common.proto
