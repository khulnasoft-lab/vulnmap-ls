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
	"github.com/rs/zerolog/log"

	"github.com/khulnasoft-lab/vulnmap-ls/application/config"
	"github.com/khulnasoft-lab/vulnmap-ls/infrastructure/vulnmap_api"
)

func (sc *Scanner) isLocalEngineEnabled(sastResponse vulnmap_api.SastResponse) bool {
	log.Debug().Any("sastResponse", sastResponse).Msg("sast response")
	return sastResponse.SastEnabled && sastResponse.LocalCodeEngine.Enabled
}

func (sc *Scanner) updateCodeApiLocalEngine(sastResponse vulnmap_api.SastResponse) {
	config.CurrentConfig().SetVulnmapCodeApi(sastResponse.LocalCodeEngine.Url)
	api := config.CurrentConfig().VulnmapCodeApi()
	log.Debug().Str("vulnmapCodeApi", api).Msg("updated Vulnmap Code API Local Engine")
}
