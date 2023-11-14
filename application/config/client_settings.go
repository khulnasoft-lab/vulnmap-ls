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
	"strconv"

	"github.com/rs/zerolog/log"
)

const (
	ActivateVulnmapOssKey       = "ACTIVATE_VULNMAP_OPEN_SOURCE"
	ActivateVulnmapCodeKey      = "ACTIVATE_VULNMAP_CODE"
	ActivateVulnmapIacKey       = "ACTIVATE_VULNMAP_IAC"
	ActivateVulnmapContainerKey = "ACTIVATE_VULNMAP_CONTAINER"
	ActivateVulnmapAdvisorKey   = "ACTIVATE_VULNMAP_ADVISOR"
	SendErrorReportsKey      = "SEND_ERROR_REPORTS"
	Organization             = "VULNMAP_CFG_ORG"
	EnableTelemetry          = "VULNMAP_CFG_DISABLE_ANALYTICS"
)

func (c *Config) clientSettingsFromEnv() {
	c.productEnablementFromEnv()
	c.errorReportsEnablementFromEnv()
	c.orgFromEnv()
	c.telemetryEnablementFromEnv()
	c.path = os.Getenv("PATH")
}

func (c *Config) orgFromEnv() {
	org := os.Getenv(Organization)
	if org != "" {
		c.SetOrganization(org)
	}
}

func (c *Config) errorReportsEnablementFromEnv() {
	errorReports := os.Getenv(SendErrorReportsKey)
	if errorReports == "false" {
		c.SetErrorReportingEnabled(false)
	} else {
		c.SetErrorReportingEnabled(true)
	}
}

func (c *Config) productEnablementFromEnv() {
	oss := os.Getenv(ActivateVulnmapOssKey)
	code := os.Getenv(ActivateVulnmapCodeKey)
	iac := os.Getenv(ActivateVulnmapIacKey)
	container := os.Getenv(ActivateVulnmapContainerKey)
	advisor := os.Getenv(ActivateVulnmapAdvisorKey)

	if oss != "" {
		parseBool, err := strconv.ParseBool(oss)
		if err != nil {
			log.Debug().Err(err).Str("method", "clientSettingsFromEnv").Msgf("couldn't parse oss config %s", oss)
		}
		c.isVulnmapOssEnabled.Set(parseBool)
	}

	if code != "" {
		parseBool, err := strconv.ParseBool(code)
		if err != nil {
			log.Debug().Err(err).Str("method", "clientSettingsFromEnv").Msgf("couldn't parse code config %s", code)
		}
		c.isVulnmapCodeEnabled.Set(parseBool)
	}

	if iac != "" {
		parseBool, err := strconv.ParseBool(iac)
		if err != nil {
			log.Debug().Err(err).Str("method", "clientSettingsFromEnv").Msgf("couldn't parse iac config %s", iac)
		}
		c.isVulnmapIacEnabled.Set(parseBool)
	}

	if container != "" {
		parseBool, err := strconv.ParseBool(container)
		if err != nil {
			log.Debug().Err(err).Str("method", "clientSettingsFromEnv").Msgf("couldn't parse container config %s", container)
		}
		c.isVulnmapContainerEnabled.Set(parseBool)
	}
	if advisor != "" {
		parseBool, err := strconv.ParseBool(advisor)
		if err != nil {
			log.Debug().Err(err).Str("method", "clientSettingsFromEnv").Msgf("couldn't parse advisor config %s", advisor)
		}
		c.isVulnmapAdvisorEnabled.Set(parseBool)
	}
}
