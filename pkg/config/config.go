/*
 * Copyright 2021.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package config

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/bluestealth/awsiamplugin/pkg/plugin"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	clientrest "k8s.io/client-go/rest"
	clientapi "k8s.io/client-go/tools/clientcmd/api"
)

type AwsIamOptions struct {
	Region               string                                 `json:"region"          yaml:"region"`
	ClusterID            string                                 `json:"cluster-id"      yaml:"cluster-id"`
	AssumeRoleARN        string                                 `json:"role-name"       yaml:"role-name"`
	AssumeRoleExternalID string                                 `json:"external-id"     yaml:"external-id"`
	SessionName          string                                 `json:"session-name"    yaml:"session-name"`
	ForwardSessionName   bool                                   `json:"forward-session" yaml:"forward-session"`
	Persist              clientrest.AuthProviderConfigPersister `json:"-"               yaml:"-"`
}

// EKSClusterConfig returns a rest config which uses aws iam credentials
// to authenticate to an EKS cluster
func EKSClusterConfig(ctx context.Context, session aws.Config, iamOptions AwsIamOptions) (kubeConfig *clientrest.Config, err error) {
	var client *eks.Client
	var credentials aws.CredentialsProvider
	var response *eks.DescribeClusterOutput

	if iamOptions.AssumeRoleARN != "" {
		var sessionName string
		stsClient := sts.NewFromConfig(session, func(options *sts.Options) {
			options.Region = iamOptions.Region
		})

		if iamOptions.ForwardSessionName {
			var identity *sts.GetCallerIdentityOutput
			if identity, err = stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err != nil {
				return
			}
			userIDParts := strings.Split(*identity.UserId, ":")
			if len(userIDParts) == 2 {
				sessionName = userIDParts[1]
			}
		} else if iamOptions.SessionName != "" {
			sessionName = iamOptions.SessionName
		}

		credentials = stscreds.NewAssumeRoleProvider(stsClient, iamOptions.AssumeRoleARN, func(stsOptions *stscreds.AssumeRoleOptions) {
			if sessionName != "" {
				stsOptions.RoleSessionName = sessionName
			}
			if iamOptions.AssumeRoleExternalID != "" {
				stsOptions.ExternalID = &iamOptions.AssumeRoleExternalID
			}
		})
	}

	client = eks.NewFromConfig(session, func(options *eks.Options) {
		options.Credentials = credentials
		options.Region = iamOptions.Region
	})

	if response, err = client.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: &iamOptions.ClusterID}); err != nil {
		err = fmt.Errorf("failed to descriibe cluster: %w", err)
		return
	}

	var caData []byte
	if caData, err = base64.StdEncoding.DecodeString(*response.Cluster.CertificateAuthority.Data); err != nil {
		return
	}

	// Generate configuration
	kubeConfig = &clientrest.Config{
		Host: aws.ToString(response.Cluster.Endpoint),
		AuthProvider: &clientapi.AuthProviderConfig{
			Name: plugin.Name,
			Config: map[string]string{
				plugin.RegionName:         iamOptions.Region,
				plugin.ClusterIdName:      iamOptions.ClusterID,
				plugin.ForwardSessionName: strconv.FormatBool(iamOptions.ForwardSessionName),
				plugin.SessionName:        iamOptions.SessionName,
				plugin.RoleName:           iamOptions.AssumeRoleARN,
				plugin.ExternalIdName:     iamOptions.AssumeRoleExternalID,
			},
		},
		AuthConfigPersister: iamOptions.Persist,
		TLSClientConfig: clientrest.TLSClientConfig{
			CAData: caData,
		},
		UserAgent: "embedded aws iam authenticator",
	}

	return
}
