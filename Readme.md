### AWS IAM Kube Auth Plugin
A library to allow use of aws-iam-authenticator without exec

#### Usage
```go
package main

import (
    awsConfig "github.com/aws/aws-sdk-go-v2/config"
    awsKubeConfig "github.com/bluestealth/awsiamplugin/pkg/config"
    "k8s.io/client-go/kubernetes"
)

func main() {
    ctx := context.Background()
    var client *kubernetes.Clientset
    session, err := awsConfig.LoadDefaultConfig(ctx)
    if err != nil {
        panic(err)
    }
    config, err := awsKubeConfig.EKSClusterConfig(ctx, session, awsKubeConfig.AwsIamOptions{
        Region:               "us-east-2",
        ClusterID:            "my-awesome-eks-cluster",
        ForwardSessionName:   true,
    })
    client, err = kubernetes.NewForConfig(config)
    if err != nil {
        panic(err)
    }
    ...
```