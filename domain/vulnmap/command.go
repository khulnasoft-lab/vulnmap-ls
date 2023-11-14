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

package vulnmap

import (
	"context"
	"sync"

	"github.com/khulnasoft-lab/go-application-framework/pkg/auth"

	"github.com/khulnasoft-lab/vulnmap-ls/internal/lsp"
)

const (
	NavigateToRangeCommand       = "vulnmap.navigateToRange"
	WorkspaceScanCommand         = "vulnmap.workspace.scan"
	WorkspaceFolderScanCommand   = "vulnmap.workspaceFolder.scan"
	OpenBrowserCommand           = "vulnmap.openBrowser"
	LoginCommand                 = "vulnmap.login"
	CopyAuthLinkCommand          = "vulnmap.copyAuthLink"
	LogoutCommand                = "vulnmap.logout"
	TrustWorkspaceFoldersCommand = "vulnmap.trustWorkspaceFolders"
	OpenLearnLesson              = "vulnmap.openLearnLesson"
	GetLearnLesson               = "vulnmap.getLearnLesson"
	GetSettingsSastEnabled       = "vulnmap.getSettingsSastEnabled"
	GetActiveUserCommand         = "vulnmap.getActiveUser"
	ReportAnalyticsCommand       = "vulnmap.reportAnalytics"

	// Vulnmap Code specific commands
	CodeFixCommand        = "vulnmap.code.fix"
	CodeSubmitFixFeedback = "vulnmap.code.submitFixFeedback"
)

var (
	DefaultOpenBrowserFunc = func(url string) { auth.OpenBrowser(url) }
)

type Command interface {
	Command() CommandData
	Execute(ctx context.Context) (any, error)
}

type CommandData struct {
	/**
	 * Title of the command, like `save`.
	 */
	Title string
	/**
	 * The identifier of the actual command handler.
	 */
	CommandId string
	/**
	 * Arguments that the command handler should be
	 * invoked with.
	 */
	Arguments []any
}

type CommandName string

type CommandService interface {
	ExecuteCommandData(ctx context.Context, commandData CommandData, server lsp.Server) (any, error)
}

type CommandServiceMock struct {
	m                sync.Mutex
	executedCommands []CommandData
}

func NewCommandServiceMock() *CommandServiceMock {
	return &CommandServiceMock{}
}

// todo:test
func (service *CommandServiceMock) ExecuteCommandData(_ context.Context, command CommandData, server lsp.Server) (any, error) {
	service.m.Lock()
	service.executedCommands = append(service.executedCommands, command)
	service.m.Unlock()
	return nil, nil
}

func (service *CommandServiceMock) ExecutedCommands() []CommandData {
	service.m.Lock()
	cmds := service.executedCommands
	service.m.Unlock()
	return cmds
}
