module github.com/openbao/go-kms-wrapping/wrappers/ovhkms/v2

go 1.24.0

replace github.com/openbao/go-kms-wrapping/v2 => ../../

require (
	github.com/google/uuid v1.6.0
	github.com/openbao/go-kms-wrapping/v2 v2.6.0
	github.com/ovh/okms-sdk-go v0.5.1
)

require (
	github.com/apapsch/go-jsonmerge/v2 v2.0.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.8 // indirect
	github.com/hashicorp/go-secure-stdlib/parseutil v0.2.0 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.7 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/oapi-codegen/runtime v1.1.2 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	golang.org/x/crypto v0.42.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
	google.golang.org/protobuf v1.36.10 // indirect
)
