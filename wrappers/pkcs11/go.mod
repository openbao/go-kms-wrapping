module github.com/openbao/go-kms-wrapping/wrappers/pkcs11/v2

go 1.22.1

replace github.com/openbao/go-kms-wrapping/v2 => ../../

require (
	github.com/miekg/pkcs11 v1.1.2-0.20231115102856-9078ad6b9d4b
	github.com/openbao/go-kms-wrapping/v2 v2.0.0-00010101000000-000000000000
)

require (
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
)

retract [v2.0.0, v2.0.2]
