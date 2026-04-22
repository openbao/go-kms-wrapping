module github.com/openbao/go-kms-wrapping/kms/pkcs11/v2

go 1.25.0

replace github.com/openbao/go-kms-wrapping/v2 => ../../

require (
	github.com/go-viper/mapstructure/v2 v2.5.0
	github.com/miekg/pkcs11 v1.1.2
	github.com/openbao/go-kms-wrapping/v2 v2.7.0
	github.com/stretchr/testify v1.11.1
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/fatih/color v1.13.0 // indirect
	github.com/hashicorp/go-hclog v1.6.3 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	golang.org/x/sys v0.21.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
