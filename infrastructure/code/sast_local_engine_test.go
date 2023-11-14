/*
 * © 2023 Khulnasoft Limited
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

package code

import (
	"slices"
	"testing"

	"github.com/khulnasoft-lab/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"

	"github.com/khulnasoft-lab/vulnmap-ls/application/config"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/observability/error_reporting"
	"github.com/khulnasoft-lab/vulnmap-ls/infrastructure/vulnmap_api"
	"github.com/khulnasoft-lab/vulnmap-ls/internal/notification"
)

func TestIsLocalEngine(t *testing.T) {
	apiClient := &vulnmap_api.FakeApiClient{
		CodeEnabled: true,
		ApiError:    nil,
	}

	mockedSastResponse := vulnmap_api.SastResponse{
		SastEnabled: true,
		LocalCodeEngine: vulnmap_api.LocalCodeEngine{
			AllowCloudUpload: false,
			Url:              "http://local.engine",
			Enabled:          true,
		},
	}

	scanner := &Scanner{
		VulnmapApiClient: apiClient,
		errorReporter: error_reporting.NewTestErrorReporter(),
		notifier:      notification.NewNotifier(),
	}

	t.Run("should return true if SAST and local engine is enabled is disabled", func(t *testing.T) {
		enabled := scanner.isLocalEngineEnabled(mockedSastResponse)
		assert.True(t, enabled)
	})

	t.Run("should return false if SAST is enabled local engine is disabled", func(t *testing.T) {
		mockedSastResponse.LocalCodeEngine.Enabled = false
		enabled := scanner.isLocalEngineEnabled(mockedSastResponse)
		assert.False(t, enabled)
	})

	t.Run("should return false if SAST is enabled local engine is disabled", func(t *testing.T) {
		mockedSastResponse.LocalCodeEngine.Enabled = true
		mockedSastResponse.SastEnabled = false
		enabled := scanner.isLocalEngineEnabled(mockedSastResponse)
		assert.False(t, enabled)
	})

	t.Run("should update Vulnmap Code API if local-engine is enabled", func(t *testing.T) {
		mockedSastResponse.SastEnabled = true
		mockedSastResponse.LocalCodeEngine.Enabled = true
		scanner.updateCodeApiLocalEngine(mockedSastResponse)
		assert.Equal(t, mockedSastResponse.LocalCodeEngine.Url, config.CurrentConfig().VulnmapCodeApi())
		additionalAuthUrls := config.CurrentConfig().Engine().GetConfiguration().GetStringSlice(configuration.
			AUTHENTICATION_ADDITIONAL_URLS)
		assert.True(t, slices.Contains(additionalAuthUrls, mockedSastResponse.LocalCodeEngine.Url))
	})
}
