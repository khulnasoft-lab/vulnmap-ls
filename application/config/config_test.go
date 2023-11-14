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

package config

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/khulnasoft-lab/vulnmap-ls/infrastructure/cli/cli_constants"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"

	"github.com/khulnasoft-lab/go-application-framework/pkg/auth"
	"github.com/khulnasoft-lab/go-application-framework/pkg/configuration"

	"github.com/khulnasoft-lab/vulnmap-ls/internal/lsp"
)

func TestSetToken(t *testing.T) {
	t.Run("Legacy Token authentication", func(t *testing.T) {
		token := uuid.New().String()
		config := New()
		SetCurrentConfig(config)
		config.SetToken(token)
		assert.Equal(t, config.Token(), token)
		assert.NotEqual(t, config.Engine().GetConfiguration().Get(auth.CONFIG_KEY_OAUTH_TOKEN), token)
		assert.Equal(t, config.Engine().GetConfiguration().Get(configuration.AUTHENTICATION_TOKEN), token)
	})
	t.Run("OAuth Token authentication", func(t *testing.T) {
		config := New()
		SetCurrentConfig(config)
		config.authenticationMethod = lsp.OAuthAuthentication
		marshal, err := json.Marshal(oauth2.Token{AccessToken: t.Name()})
		assert.NoError(t, err)
		oauthString := string(marshal)

		config.SetToken(oauthString)

		assert.Equal(t, oauthString, config.Token())
		assert.Equal(t, oauthString, config.Engine().GetConfiguration().Get(auth.CONFIG_KEY_OAUTH_TOKEN))
	})
}

func TestConfigDefaults(t *testing.T) {
	c := New()

	assert.True(t, c.IsTelemetryEnabled(), "Telemetry should be enabled by default")
	assert.True(t, c.IsErrorReportingEnabled(), "Error Reporting should be enabled by default")
	assert.False(t, c.IsVulnmapAdvisorEnabled(), "Advisor should be disabled by default")
	assert.False(t, c.IsVulnmapCodeEnabled(), "Vulnmap Code should be disabled by default")
	assert.False(t, c.IsVulnmapContainerEnabled(), "Vulnmap Container should be enabled by default")
	assert.True(t, c.IsVulnmapOssEnabled(), "Vulnmap Open Source should be enabled by default")
	assert.True(t, c.IsVulnmapIacEnabled(), "Vulnmap IaC should be enabled by default")
	assert.Equal(t, "", c.LogPath(), "Logpath should be empty by default")
	assert.Equal(t, "md", c.Format(), "Output format should be md by default")
	assert.Equal(t, lsp.DefaultSeverityFilter(), c.FilterSeverity(), "All severities should be enabled by default")
	assert.Empty(t, c.trustedFolders)
	assert.Equal(t, lsp.TokenAuthentication, c.authenticationMethod)
}

func Test_TokenChanged_ChannelsInformed(t *testing.T) {
	// Arrange
	c := New()
	tokenChangedChannel := c.TokenChangesChannel()

	// Act
	// There's a 1 in 5 undecillion (5 * 10^36) chance for a collision here so let's hold our fingers
	c.SetToken(uuid.New().String())

	// Assert
	// This will either pass the test or fail by deadlock immediately if SetToken did not write to the change channels,
	// therefore there's no need for assert.Eventually
	assert.Eventuallyf(t, func() bool {
		<-tokenChangedChannel
		return true
	}, 5*time.Second, time.Millisecond, "Expected token changes channel to be informed, but it was not")

}

func Test_TokenChangedToSameToken_ChannelsNotInformed(t *testing.T) {
	// Arrange
	c := New()
	tokenChangedChannel := c.TokenChangesChannel()
	token := c.Token()

	// Act
	c.SetToken(token)

	// Assert
	select {
	case newToken := <-tokenChangedChannel:
		assert.Fail(t, "Expected empty token changes channel, but received new token (%v)", newToken)
	default:
		// This case triggers when tokenChangedChannel is empty, test passes
	}
}

func Test_VulnmapCodeAnalysisTimeoutReturnsTimeoutFromEnvironment(t *testing.T) {
	t.Setenv(vulnmapCodeTimeoutKey, "1s")
	duration, _ := time.ParseDuration("1s")
	assert.Equal(t, duration, vulnmapCodeAnalysisTimeoutFromEnv())
}

func Test_VulnmapCodeAnalysisTimeoutReturnsDefaultIfNoEnvVariableFound(t *testing.T) {
	t.Setenv(vulnmapCodeTimeoutKey, "")
	assert.Equal(t, 12*time.Hour, vulnmapCodeAnalysisTimeoutFromEnv())
}

func Test_updatePath(t *testing.T) {
	t.Setenv("PATH", "a")
	c := New()
	c.updatePath("b")
	assert.Contains(t, c.path, string(os.PathListSeparator)+"b")
	assert.Contains(t, c.path, "a"+string(os.PathListSeparator))
}

func Test_loadFile(t *testing.T) {
	t.Setenv("A", "")
	t.Setenv("C", "")
	_ = os.Unsetenv("A")
	_ = os.Unsetenv("C")
	envData := []byte("A=B\nC=D")
	file, err := os.CreateTemp(".", "config_test_loadFile")
	if err != nil {
		assert.Fail(t, "Couldn't create temp file", err)
	}
	defer func(file *os.File) {
		_ = file.Close()
		_ = os.Remove(file.Name())
	}(file)
	if err != nil {
		assert.Fail(t, "Couldn't create test file")
	}
	_, _ = file.Write(envData)
	if err != nil {
		assert.Fail(t, "Couldn't write to test file")
	}

	CurrentConfig().loadFile(file.Name())

	assert.Equal(t, "B", os.Getenv("A"))
	assert.Equal(t, "D", os.Getenv("C"))
}

func TestVulnmapCodeApi(t *testing.T) {
	t.Run("endpoint not provided", func(t *testing.T) {

		codeApiEndpoint, _ := getCodeApiUrlFromCustomEndpoint("")
		assert.Equal(t, "https://deeproxy.vulnmap.khulnasoft.com", codeApiEndpoint)
	})

	t.Run("endpoint provided without 'app' prefix", func(t *testing.T) {

		endpoint := "https://vulnmap.khulnasoft.com/api/v1"
		codeApiEndpoint, _ := getCodeApiUrlFromCustomEndpoint(endpoint)
		assert.Equal(t, "https://deeproxy.vulnmap.khulnasoft.com", codeApiEndpoint)
	})

	t.Run("endpoint provided with 'app' prefix with v1 suffix", func(t *testing.T) {

		endpoint := "https://app.vulnmap.khulnasoft.com/api/v1"
		codeApiEndpoint, _ := getCodeApiUrlFromCustomEndpoint(endpoint)
		assert.Equal(t, "https://deeproxy.vulnmap.khulnasoft.com", codeApiEndpoint)
	})

	t.Run("endpoint provided with 'app' prefix without v1 suffix", func(t *testing.T) {

		endpoint := "https://app.vulnmap.khulnasoft.com/api"
		codeApiEndpoint, _ := getCodeApiUrlFromCustomEndpoint(endpoint)
		assert.Equal(t, "https://deeproxy.vulnmap.khulnasoft.com", codeApiEndpoint)
	})

	t.Run("endpoint provided with 'api' prefix", func(t *testing.T) {
		endpoint := "https://api.vulnmap.khulnasoft.com"
		codeApiEndpoint, _ := getCodeApiUrlFromCustomEndpoint(endpoint)
		assert.Equal(t, "https://deeproxy.vulnmap.khulnasoft.com", codeApiEndpoint)
	})

	t.Run("proxy endpoint provided via 'DEEPROXY_API_URL' environment variable", func(t *testing.T) {
		customDeeproxyUrl := "https://deeproxy.custom.url.vulnmap.khulnasoft.com"
		t.Setenv("DEEPROXY_API_URL", customDeeproxyUrl)
		codeApiEndpoint, _ := getCodeApiUrlFromCustomEndpoint("")
		assert.Equal(t, customDeeproxyUrl, codeApiEndpoint)
	})
}

func Test_SetSeverityFilter(t *testing.T) {
	t.Run("Saves filter", func(t *testing.T) {
		c := New()
		c.SetSeverityFilter(lsp.NewSeverityFilter(true, true, false, false))
		assert.Equal(t, lsp.NewSeverityFilter(true, true, false, false), c.FilterSeverity())
	})

	t.Run("Returns correctly", func(t *testing.T) {
		c := New()
		lowExcludedFilter := lsp.NewSeverityFilter(true, true, false, false)

		modified := c.SetSeverityFilter(lowExcludedFilter)
		assert.True(t, modified)

		modified = c.SetSeverityFilter(lowExcludedFilter)
		assert.False(t, modified)
	})
}

func Test_ManageBinariesAutomatically(t *testing.T) {
	c := New()

	// case: standalone, manage true
	c.SetManageBinariesAutomatically(true)
	assert.True(t, c.ManageBinariesAutomatically())
	assert.True(t, c.ManageCliBinariesAutomatically())

	// case: standalone, manage false
	c.SetManageBinariesAutomatically(false)
	assert.False(t, c.ManageBinariesAutomatically())
	assert.False(t, c.ManageCliBinariesAutomatically())

	// case: extension, manage true
	c.SetManageBinariesAutomatically(true)
	c.Engine().GetConfiguration().Set(cli_constants.EXECUTION_MODE_KEY, cli_constants.EXECUTION_MODE_VALUE_EXTENSION)
	assert.True(t, c.ManageBinariesAutomatically())
	assert.False(t, c.ManageCliBinariesAutomatically())
}

func Test_IsFedramp(t *testing.T) {
	t.Run("short hostname", func(t *testing.T) {
		c := New()
		c.UpdateApiEndpoints("https://api.vulnmap.khulnasoft.com")
		assert.False(t, c.IsFedramp())
	})

	t.Run("fedramp hostname", func(t *testing.T) {
		c := New()
		c.UpdateApiEndpoints("https://api.fedramp.vulnmapgov.io")
		assert.True(t, c.IsFedramp())
	})

	t.Run("non-fedramp hostname", func(t *testing.T) {
		c := New()
		c.UpdateApiEndpoints("https://api.fedddddddddramp.vulnmapgov.io")
		assert.True(t, c.IsFedramp())
	})

}

func Test_IsTelemetryEnabled(t *testing.T) {
	t.Setenv(EnableTelemetry, "1")
	c := New()

	// case: disabled via env var
	assert.False(t, c.IsTelemetryEnabled())
	assert.True(t, c.Engine().GetConfiguration().GetBool(configuration.ANALYTICS_DISABLED))

	// case: enabled via setter
	c.SetTelemetryEnabled(true)
	assert.True(t, c.IsTelemetryEnabled())
	assert.False(t, c.Engine().GetConfiguration().GetBool(configuration.ANALYTICS_DISABLED))

	// case: disabled via setter
	c.SetTelemetryEnabled(false)
	assert.False(t, c.IsTelemetryEnabled())
	assert.True(t, c.Engine().GetConfiguration().GetBool(configuration.ANALYTICS_DISABLED))

}
