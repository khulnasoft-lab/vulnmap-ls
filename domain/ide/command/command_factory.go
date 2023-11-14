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
	"fmt"

	"github.com/khulnasoft-lab/vulnmap-ls/application/config"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/ide"
	noti "github.com/khulnasoft-lab/vulnmap-ls/domain/ide/notification"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/vulnmap"
	"github.com/khulnasoft-lab/vulnmap-ls/infrastructure/learn"
	"github.com/khulnasoft-lab/vulnmap-ls/infrastructure/vulnmap_api"
	"github.com/khulnasoft-lab/vulnmap-ls/internal/lsp"
)

func CreateFromCommandData(
	commandData vulnmap.CommandData,
	srv lsp.Server,
	authService vulnmap.AuthenticationService,
	learnService learn.Service,
	notifier noti.Notifier,
	issueProvider ide.IssueProvider,
	codeApiClient VulnmapCodeHttpClient,
) (vulnmap.Command, error) {

	switch commandData.CommandId {
	case vulnmap.NavigateToRangeCommand:
		return &navigateToRangeCommand{command: commandData, srv: srv}, nil
	case vulnmap.WorkspaceScanCommand:
		return &workspaceScanCommand{command: commandData, srv: srv}, nil
	case vulnmap.WorkspaceFolderScanCommand:
		return &workspaceFolderScanCommand{command: commandData, srv: srv}, nil
	case vulnmap.OpenBrowserCommand:
		return &openBrowserCommand{command: commandData}, nil
	case vulnmap.LoginCommand:
		return &loginCommand{command: commandData, authService: authService, notifier: notifier}, nil
	case vulnmap.CopyAuthLinkCommand:
		return &copyAuthLinkCommand{command: commandData, authService: authService, notifier: notifier}, nil
	case vulnmap.LogoutCommand:
		return &logoutCommand{command: commandData, authService: authService}, nil
	case vulnmap.TrustWorkspaceFoldersCommand:
		return &trustWorkspaceFoldersCommand{command: commandData, notifier: notifier}, nil
	case vulnmap.GetLearnLesson:
		return &getLearnLesson{command: commandData, srv: srv, learnService: learnService}, nil
	case vulnmap.OpenLearnLesson:
		return &openLearnLesson{command: commandData, srv: srv, learnService: learnService}, nil
	case vulnmap.GetSettingsSastEnabled:
		apiClient := vulnmap_api.NewVulnmapApiClient(config.CurrentConfig().Engine().GetNetworkAccess().GetHttpClient)
		return &sastEnabled{command: commandData, apiClient: apiClient}, nil
	case vulnmap.GetActiveUserCommand:
		return &getActiveUser{command: commandData, authService: authService, notifier: notifier}, nil
	case vulnmap.ReportAnalyticsCommand:
		return &reportAnalyticsCommand{command: commandData}, nil
	case vulnmap.CodeFixCommand:
		return &fixCodeIssue{command: commandData, issueProvider: issueProvider, notifier: notifier}, nil
	case vulnmap.CodeSubmitFixFeedback:
		return &codeFixFeedback{command: commandData, apiClient: codeApiClient}, nil
	}

	return nil, fmt.Errorf("unknown command %v", commandData)
}
