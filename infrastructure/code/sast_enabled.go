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
	"github.com/khulnasoft-lab/vulnmap-ls/domain/vulnmap"
	"github.com/khulnasoft-lab/vulnmap-ls/infrastructure/vulnmap_api"
	"github.com/khulnasoft-lab/vulnmap-ls/internal/data_structure"
)

const codeDisabledInOrganisationMessageText = "It looks like your organization has disabled Vulnmap Code. " +
	"You can easily enable it by clicking on 'Enable Vulnmap Code'. " +
	"This will open your organization settings in your browser."

const enableVulnmapCodeMessageActionItemTitle vulnmap.MessageAction = "Enable Vulnmap Code"
const closeMessageActionItemTitle vulnmap.MessageAction = "Close"

func (sc *Scanner) isSastEnabled(sastResponse vulnmap_api.SastResponse) bool {
	if !sastResponse.SastEnabled {
		// this is processed in the listener registered to translate into the right client protocol
		actionCommandMap := data_structure.NewOrderedMap[vulnmap.MessageAction, vulnmap.CommandData]()
		commandData := vulnmap.CommandData{
			Title:     vulnmap.OpenBrowserCommand,
			CommandId: vulnmap.OpenBrowserCommand,
			Arguments: []any{getCodeEnablementUrl()},
		}

		actionCommandMap.Add(enableVulnmapCodeMessageActionItemTitle, commandData)
		actionCommandMap.Add(closeMessageActionItemTitle, vulnmap.CommandData{})

		sc.notifier.Send(vulnmap.ShowMessageRequest{
			Message: codeDisabledInOrganisationMessageText,
			Type:    vulnmap.Warning,
			Actions: actionCommandMap,
		})
		return false
	}

	getCodeSettings().SetAutofixEnabled(sastResponse.AutofixEnabled)

	return true
}
