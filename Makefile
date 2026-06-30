.PHONY: tidy
tidy:
	find . -name go.mod -execdir go mod tidy \;

.PHONY: fmt
fmt:
	go tool -modfile=tools/go.mod gofumpt -w .

.PHONY: proto
proto:
	protoc --go_out=. --go_opt=paths=source_relative ./types.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative ./plugin/pb/plugin.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative ./plugin/pb/kms/plugin.proto
