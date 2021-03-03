module github.com/bluestealth/awsiamplugin

go 1.16

replace sigs.k8s.io/aws-iam-authenticator => github.com/bluestealth/aws-iam-authenticator v0.5.6

require (
	github.com/aws/aws-sdk-go-v2 v1.2.0
	github.com/aws/aws-sdk-go-v2/config v1.1.1
	github.com/aws/aws-sdk-go-v2/credentials v1.1.1
	github.com/aws/aws-sdk-go-v2/service/eks v1.1.1
	github.com/aws/aws-sdk-go-v2/service/sts v1.1.1
	k8s.io/client-go v0.20.4
	k8s.io/klog/v2 v2.5.0
	sigs.k8s.io/aws-iam-authenticator v0.5.2
)
