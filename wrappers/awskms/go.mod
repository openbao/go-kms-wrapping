module github.com/openbao/go-kms-wrapping/wrappers/awskms/v2

go 1.24.0

replace github.com/openbao/go-kms-wrapping/v2 => ../../

require (
	github.com/aws/aws-sdk-go-v2 v1.41.1
	github.com/aws/aws-sdk-go-v2/service/kms v1.49.5
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-hclog v1.6.3
	github.com/hashicorp/go-secure-stdlib/awsutil/v2 v2.1.2
	github.com/openbao/go-kms-wrapping/v2 v2.2.0
	github.com/stretchr/testify v1.10.0
)

require (
	github.com/aws/aws-sdk-go-v2/config v1.28.5 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.17.46 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.20 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/iam v1.38.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.12.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.12.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.24.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.28.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.33.1 // indirect
	github.com/aws/smithy-go v1.24.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/fatih/color v1.18.0 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.9 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.6 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	golang.org/x/sys v0.29.0 // indirect
	google.golang.org/protobuf v1.36.4 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

retract [v2.0.0, v2.0.8]
