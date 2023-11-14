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
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestGetEnabledProducts_DefaultValues(t *testing.T) {
	t.Setenv(ActivateVulnmapOssKey, "set it to anything to make sure it is reset")
	t.Setenv(ActivateVulnmapCodeKey, "set it to anything to make sure it is reset")
	t.Setenv(ActivateVulnmapIacKey, "set it to anything to make sure it is reset")
	t.Setenv(ActivateVulnmapContainerKey, "set it to anything to make sure it is reset")
	t.Setenv(ActivateVulnmapAdvisorKey, "set it to anything to make sure it is reset")
	_ = os.Unsetenv(ActivateVulnmapOssKey)
	_ = os.Unsetenv(ActivateVulnmapCodeKey)
	_ = os.Unsetenv(ActivateVulnmapIacKey)
	_ = os.Unsetenv(ActivateVulnmapContainerKey)
	_ = os.Unsetenv(ActivateVulnmapAdvisorKey)
	SetCurrentConfig(New())

	currentConfig.clientSettingsFromEnv()

	assert.Equal(t, true, CurrentConfig().IsVulnmapOssEnabled())
	assert.Equal(t, false, CurrentConfig().IsVulnmapCodeEnabled())
	assert.Equal(t, true, CurrentConfig().IsVulnmapIacEnabled())
	assert.Equal(t, false, CurrentConfig().IsVulnmapContainerEnabled())
	assert.Equal(t, false, CurrentConfig().IsVulnmapAdvisorEnabled())
}

func TestConfig_IsErrorReportingEnabledFromEnv_DefaultValues(t *testing.T) {
	t.Setenv(SendErrorReportsKey, "set it to anything to make sure it is reset")
	_ = os.Unsetenv(SendErrorReportsKey)
	SetCurrentConfig(New())
	CurrentConfig().clientSettingsFromEnv()

	assert.Equal(t, true, CurrentConfig().IsErrorReportingEnabled())
}
func TestConfig_IsErrorReportingEnabledFromEnv(t *testing.T) {
	t.Setenv(SendErrorReportsKey, "true")
	SetCurrentConfig(New())
	CurrentConfig().clientSettingsFromEnv()

	assert.Equal(t, true, CurrentConfig().IsErrorReportingEnabled())
}

func TestConfig_IsErrorReportingEnabledFromEnv_Error(t *testing.T) {
	t.Setenv(SendErrorReportsKey, "hurz")
	SetCurrentConfig(New())
	CurrentConfig().clientSettingsFromEnv()

	assert.Equal(t, true, CurrentConfig().IsErrorReportingEnabled())
}

func TestConfig_OrganizationFromEnv(t *testing.T) {
	orgUuid, _ := uuid.NewRandom()
	expectedOrgId := orgUuid.String()
	t.Setenv(Organization, expectedOrgId)
	SetCurrentConfig(New())
	CurrentConfig().clientSettingsFromEnv()

	assert.Equal(t, expectedOrgId, CurrentConfig().Organization())
}

func TestConfig_EnableTelemetryFromEnv(t *testing.T) {
	t.Setenv(EnableTelemetry, "0")
	SetCurrentConfig(New())
	CurrentConfig().clientSettingsFromEnv()

	assert.Equal(t, true, CurrentConfig().IsTelemetryEnabled())
}

func TestConfig_DisableTelemetryFromEnv(t *testing.T) {
	t.Setenv(EnableTelemetry, "1")
	SetCurrentConfig(New())
	CurrentConfig().clientSettingsFromEnv()

	assert.Equal(t, false, CurrentConfig().IsTelemetryEnabled())
}

func TestInitializeDefaultProductEnablement(t *testing.T) {
	t.Setenv(ActivateVulnmapOssKey, "false")
	t.Setenv(ActivateVulnmapCodeKey, "true")
	t.Setenv(ActivateVulnmapIacKey, "false")
	t.Setenv(ActivateVulnmapAdvisorKey, "true")
	t.Setenv(ActivateVulnmapContainerKey, "true")

	SetCurrentConfig(New())

	assert.Equal(t, false, CurrentConfig().IsVulnmapOssEnabled())
	assert.Equal(t, true, CurrentConfig().IsVulnmapCodeEnabled())
	assert.Equal(t, false, CurrentConfig().IsVulnmapIacEnabled())
	assert.Equal(t, true, CurrentConfig().IsVulnmapContainerEnabled())
	assert.Equal(t, true, CurrentConfig().IsVulnmapAdvisorEnabled())
}

func TestGetEnabledProducts_Oss(t *testing.T) {
	t.Setenv(ActivateVulnmapOssKey, "false")
	CurrentConfig().clientSettingsFromEnv()
	assert.Equal(t, false, CurrentConfig().isVulnmapOssEnabled.Get())

	t.Setenv(ActivateVulnmapOssKey, "true")
	CurrentConfig().clientSettingsFromEnv()
	assert.Equal(t, true, CurrentConfig().isVulnmapOssEnabled.Get())
}

func TestGetEnabledProducts_Code(t *testing.T) {
	t.Setenv(ActivateVulnmapCodeKey, "false")
	CurrentConfig().clientSettingsFromEnv()
	assert.Equal(t, false, CurrentConfig().IsVulnmapCodeEnabled())

	t.Setenv(ActivateVulnmapCodeKey, "true")
	CurrentConfig().clientSettingsFromEnv()
	assert.Equal(t, true, CurrentConfig().IsVulnmapCodeEnabled())
}

func TestGetEnabledProducts_Iac(t *testing.T) {
	t.Setenv(ActivateVulnmapIacKey, "false")
	CurrentConfig().clientSettingsFromEnv()
	assert.Equal(t, false, CurrentConfig().IsVulnmapIacEnabled())

	t.Setenv(ActivateVulnmapIacKey, "true")
	CurrentConfig().clientSettingsFromEnv()
	assert.Equal(t, true, CurrentConfig().IsVulnmapIacEnabled())
}

func TestGetEnabledProducts_Container(t *testing.T) {
	t.Setenv(ActivateVulnmapContainerKey, "false")
	CurrentConfig().clientSettingsFromEnv()
	assert.Equal(t, false, CurrentConfig().IsVulnmapContainerEnabled())

	t.Setenv(ActivateVulnmapContainerKey, "true")
	CurrentConfig().clientSettingsFromEnv()
	assert.Equal(t, true, CurrentConfig().IsVulnmapContainerEnabled())
}

func TestGetEnabledProducts_Advisor(t *testing.T) {
	t.Setenv(ActivateVulnmapAdvisorKey, "false")
	CurrentConfig().clientSettingsFromEnv()
	assert.Equal(t, false, CurrentConfig().IsVulnmapAdvisorEnabled())

	t.Setenv(ActivateVulnmapAdvisorKey, "true")
	CurrentConfig().clientSettingsFromEnv()
	assert.Equal(t, true, CurrentConfig().IsVulnmapAdvisorEnabled())
}
