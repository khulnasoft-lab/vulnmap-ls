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

package command

import (
	"context"

	"github.com/rs/zerolog/log"

	"github.com/khulnasoft-lab/vulnmap-ls/application/config"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/vulnmap"
	"github.com/khulnasoft-lab/vulnmap-ls/infrastructure/vulnmap_api"
)

type sastEnabled struct {
	command   vulnmap.CommandData
	apiClient vulnmap_api.VulnmapApiClient
}

func (cmd *sastEnabled) Command() vulnmap.CommandData {
	return cmd.command
}

func (cmd *sastEnabled) Execute(_ context.Context) (any, error) {
	if config.CurrentConfig().Token() == "" {
		log.Info().Str("method", "sastEnabled.Execute").Msg("no token, skipping sast check")
		return nil, nil
	}
	sastResponse, err := cmd.apiClient.SastSettings()
	return sastResponse, err
}
