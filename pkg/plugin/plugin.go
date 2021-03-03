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

package plugin

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	clientrest "k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/aws/aws-sdk-go-v2/config"
	"sigs.k8s.io/aws-iam-authenticator/pkg/token"
)

const (
	Name               = "aws-iam"
	AccessTokenName    = "access-token"
	ExpiryName         = "expiry"
	RegionName         = "region"
	ClusterIdName      = "cluster-id"
	SessionName        = "session-name"
	RoleName           = "role-name"
	ExternalIdName     = "external-id"
	ForwardSessionName = "forward-session"
)

type awsIamKubeAuthPlugin struct {
	persister      clientrest.AuthProviderConfigPersister
	o              token.GetTokenOptions
	g              token.Generator
	t              token.Token
	Base           http.RoundTripper
	forwardSession bool
}

func init() {
	if err := clientrest.RegisterAuthProviderPlugin(Name, newAWSIAMAuthProvider); err != nil {
		klog.Fatalf("Failed to register aws-iam auth plugin: %v", err)
	}
}

func newAWSIAMAuthProvider(_ string, awsIamConfigMap map[string]string, persister clientrest.AuthProviderConfigPersister) (result clientrest.AuthProvider, err error) {
	plugin := &awsIamKubeAuthPlugin{
		persister: persister,
	}

	ctx := context.TODO()
	if err = plugin.parseConfig(ctx, awsIamConfigMap); err != nil {
		return
	}

	result = plugin

	return
}

// parseConfig reads awsIamConfigMap params and sets up token generator
func (i *awsIamKubeAuthPlugin) parseConfig(ctx context.Context, awsIamConfigMap map[string]string) (err error) {
	if value, ok := awsIamConfigMap[ClusterIdName]; ok {
		i.o.ClusterID = value
	} else {
		err = fmt.Errorf("%s not defined, it is a required parameter", ClusterIdName)
		return
	}

	if value, ok := awsIamConfigMap[RegionName]; ok {
		i.o.Region = value
	}

	if value, ok := awsIamConfigMap[RoleName]; ok {
		i.o.AssumeRoleARN = value
	}

	if value, ok := awsIamConfigMap[ExternalIdName]; ok {
		i.o.AssumeRoleExternalID = value
	}

	if expiryValue, ok := awsIamConfigMap[ExpiryName]; ok && expiryValue != "" {
		if tokenValue, ok := awsIamConfigMap[AccessTokenName]; ok && tokenValue != "" {
			if expiry, parseErr := time.Parse(time.RFC3339Nano, expiryValue); parseErr != nil {
				klog.Warning("failed to parse %s: %s", ExpiryName, parseErr)
			} else if expiry.After(time.Now()) {
				i.t.Token = tokenValue
				i.t.Expiration = expiry
			}
		}
	}

	if value, ok := awsIamConfigMap[ForwardSessionName]; ok {
		if forwardSession, parseErr := strconv.ParseBool(value); parseErr != nil {
			klog.Warning("failed to parse %s: %s", ForwardSessionName, parseErr)
		} else {
			i.forwardSession = forwardSession
		}
	}

	if value, ok := awsIamConfigMap[SessionName]; ok {
		i.o.SessionName = value
	}

	if i.o.Session, err = config.LoadDefaultConfig(ctx, func(options *config.LoadOptions) error {
		if i.o.Region != "" {
			options.Region = i.o.Region
		}
		return nil
	}); err != nil {
		return
	}

	if i.g, err = token.NewGenerator(i.forwardSession, false); err != nil {
		err = fmt.Errorf("failed to start generator: %w", err)
		return
	}

	if i.o.Region == "" {
		i.o.Region = i.o.Session.Region
	}

	return
}

// cloneRequest returns a clone of the provided *http.Request.
// The clone is a shallow copy of the struct and its Header map.
func cloneRequest(in *http.Request) (out *http.Request) {
	// shallow copy of the struct
	out = new(http.Request)
	*out = *in
	// deep copy of the Header
	out.Header = make(http.Header, len(in.Header))
	for k, s := range in.Header {
		out.Header[k] = append([]string(nil), s...)
	}
	return
}

// persistConfig marshals configuration into a map and calls persister
func (i *awsIamKubeAuthPlugin) persistConfig() (err error) {
	cache := map[string]string{
		ClusterIdName:      i.o.ClusterID,
		RegionName:         i.o.Region,
		RoleName:           i.o.AssumeRoleARN,
		ExternalIdName:     i.o.AssumeRoleExternalID,
		ForwardSessionName: strconv.FormatBool(i.forwardSession),
		SessionName:        i.o.SessionName,
	}

	if i.t.Token != "" && i.t.Expiration.After(time.Now()) {
		cache[AccessTokenName] = i.t.Token
		cache[ExpiryName] = i.t.Expiration.Format(time.RFC3339Nano)
	}

	if i.persister != nil {
		err = i.persister.Persist(cache)
	}

	if err != nil {
		klog.Errorf("failed to persist aws-iam identity: %v", err)
	}

	return
}

// RoundTrip overrides the base transport, injecting the authentication header
func (i *awsIamKubeAuthPlugin) RoundTrip(req *http.Request) (response *http.Response, err error) {
	var reqBodyClosed bool

	if req.Body != nil {
		defer func() {
			if !reqBodyClosed {
				_ = req.Body.Close()
			}
		}()
	}

	var bearer string
	if i.g == nil || i.o.Session.Credentials == nil {
		err = fmt.Errorf("aws-iam: Transport's Source is nil")
		return
	}
	if bearer, err = i.getToken(req.Context()); err != nil {
		return
	}

	cloned := cloneRequest(req)

	cloned.Header.Set("Authorization", fmt.Sprintf("Bearer %s", bearer))

	// req.Body is assumed to be closed by the base RoundTripper.
	reqBodyClosed = true

	// get response
	response, err = i.base().RoundTrip(cloned)

	if response != nil && response.StatusCode == http.StatusUnauthorized {
		persistErr := i.persistConfig()
		if persistErr != nil {
			klog.Errorf("failed to update aws-iam cache: %v", err)
		}
	}

	return
}

// Gets the current base transport
func (i *awsIamKubeAuthPlugin) base() http.RoundTripper {
	if i.Base != nil {
		return i.Base
	}
	return http.DefaultTransport
}

// WrapTransport stores the passed in transport as base transport
func (i *awsIamKubeAuthPlugin) WrapTransport(tripper http.RoundTripper) http.RoundTripper {
	i.Base = tripper
	return i
}

func (i *awsIamKubeAuthPlugin) Login() error {
	return nil
}

// getToken retrieves a cached token or generates a new unexpired token
func (i *awsIamKubeAuthPlugin) getToken(ctx context.Context) (bearerToken string, err error) {
	// If the token is expired, refresh the token
	if i.t.Token == "" || i.t.Expiration.Before(time.Now()) {
		if i.t, err = i.g.GetWithOptions(ctx, &i.o); err != nil {
			return
		}
	}

	persistErr := i.persistConfig()
	if persistErr != nil {
		klog.Errorf("failed to update aws-iam cache: %v", err)
	}

	bearerToken = i.t.Token

	return
}
