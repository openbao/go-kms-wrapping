module github.com/openbao/go-kms-wrapping/kms/securosyshsm/v2

replace github.com/openbao/go-kms-wrapping/v2 => ../../

go 1.25.0

require (
	github.com/mitchellh/mapstructure v1.5.0
	github.com/openbao/go-kms-wrapping/v2 v2.5.0
)

require (
	github.com/fatih/color v1.13.0 // indirect
	github.com/hashicorp/go-hclog v1.6.3 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	golang.org/x/sys v0.21.0 // indirect
)
