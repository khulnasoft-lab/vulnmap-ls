/*
 * © 2023 Khulnasoft Limited All rights reserved.
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

package cli

import (
	"strings"

	"github.com/khulnasoft-lab/go-application-framework/pkg/auth"
	"github.com/khulnasoft-lab/go-application-framework/pkg/configuration"

	"github.com/khulnasoft-lab/vulnmap-ls/application/config"
	"github.com/khulnasoft-lab/vulnmap-ls/internal/lsp"
)

const (
	ApiEnvVar                           = "VULNMAP_API"
	TokenEnvVar                         = "VULNMAP_TOKEN"
	DisableAnalyticsEnvVar              = "VULNMAP_CFG_DISABLE_ANALYTICS"
	IntegrationNameEnvVarKey            = "VULNMAP_INTEGRATION_NAME"
	IntegrationVersionEnvVarKey         = "VULNMAP_INTEGRATION_VERSION"
	IntegrationEnvironmentEnvVarKey     = "VULNMAP_INTEGRATION_ENVIRONMENT"
	IntegrationEnvironmentVersionEnvVar = "VULNMAP_INTEGRATION_ENVIRONMENT_VERSION"
	IntegrationEnvironmentEnvVarValue   = "language-server"
	VulnmapOauthTokenEnvVar                = "VULNMAP_OAUTH_TOKEN"
)

// AppendCliEnvironmentVariables Returns the input array with additional variables used in the CLI run in the form of "key=value".
// Since we append, our values are overwriting existing env variables (because exec.Cmd.Env chooses the last value
// in case of key duplications).
// appendToken indicates whether we should append the token or not. No token should be appended in cases such as authentication.
func AppendCliEnvironmentVariables(currentEnv []string, appendToken bool) (updatedEnv []string) {
	currentConfig := config.CurrentConfig()

	// remove any existing env vars that we are going to set
	valuesToRemove := map[string]bool{
		ApiEnvVar:                                true,
		TokenEnvVar:                              true,
		VulnmapOauthTokenEnvVar:                     true,
		DisableAnalyticsEnvVar:                   true,
		auth.CONFIG_KEY_OAUTH_TOKEN:              true,
		configuration.FF_OAUTH_AUTH_FLOW_ENABLED: true,
	}

	for _, s := range currentEnv {
		split := strings.Split(s, "=")
		if valuesToRemove[split[0]] {
			continue
		}
		updatedEnv = append(updatedEnv, s)
	}

	if appendToken {
		// there can only be one - highlander principle
		if currentConfig.AuthenticationMethod() == lsp.OAuthAuthentication {
			oAuthToken, err := currentConfig.TokenAsOAuthToken()
			if err == nil && len(oAuthToken.AccessToken) > 0 {
				updatedEnv = append(updatedEnv, VulnmapOauthTokenEnvVar+"="+oAuthToken.AccessToken)
			}
		} else {
			updatedEnv = append(updatedEnv, TokenEnvVar+"="+currentConfig.Token())
		}
	}
	if currentConfig.VulnmapApi() != "" {
		updatedEnv = append(updatedEnv, ApiEnvVar+"="+currentConfig.VulnmapApi())
	}
	if !currentConfig.IsTelemetryEnabled() {
		updatedEnv = append(updatedEnv, DisableAnalyticsEnvVar+"=1")
	}

	if currentConfig.IntegrationName() != "" {
		updatedEnv = append(updatedEnv, IntegrationNameEnvVarKey+"="+currentConfig.IntegrationName())
		updatedEnv = append(updatedEnv, IntegrationVersionEnvVarKey+"="+currentConfig.IntegrationVersion())
		updatedEnv = append(updatedEnv, IntegrationEnvironmentEnvVarKey+"="+currentConfig.IdeName())
		updatedEnv = append(updatedEnv, IntegrationEnvironmentVersionEnvVar+"="+currentConfig.IdeVersion())
	}

	return
}
