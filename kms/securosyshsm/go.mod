module github.com/openbao/go-kms-wrapping/kms/securosyshsm/v2

replace github.com/openbao/go-kms-wrapping/v2 => ../../

go 1.25.0

require (
	github.com/mitchellh/mapstructure v1.5.0
	github.com/openbao/go-kms-wrapping/v2 v2.5.0
)
