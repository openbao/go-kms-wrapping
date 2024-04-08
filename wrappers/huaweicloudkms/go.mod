module github.com/openbao/go-kms-wrapping/wrappers/huaweicloudkms/v2

go 1.22.1

replace github.com/openbao/go-kms-wrapping/v2 => ../../

require (
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/huaweicloud/golangsdk v0.0.0-20210831081626-d823fe11ceba
	github.com/openbao/go-kms-wrapping/v2 v2.0.0-00010101000000-000000000000
)

require (
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
)

retract [v2.0.0, v2.0.1]
