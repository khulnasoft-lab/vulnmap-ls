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

package codelens

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/khulnasoft-lab/vulnmap-ls/application/di"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/ide/converter"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/ide/workspace"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/observability/performance"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/vulnmap"
	"github.com/khulnasoft-lab/vulnmap-ls/infrastructure/code"
	"github.com/khulnasoft-lab/vulnmap-ls/internal/progress"
	"github.com/khulnasoft-lab/vulnmap-ls/internal/testutil"
)

func Test_GetCodeLensFromCommand(t *testing.T) {
	testutil.UnitTest(t)
	issue := code.FakeIssue
	command := code.FakeCommand
	codeLens := getCodeLensFromCommand(issue, command)
	assert.Equal(t, converter.ToRange(issue.Range), codeLens.Range)
	assert.Equal(t, command.CommandId, codeLens.Command.Command)
	assert.Equal(t, command.Title, codeLens.Command.Title)
	assert.Equal(t, command.Arguments, codeLens.Command.Arguments)
}

func Test_GetCodeLensForPath(t *testing.T) {
	testutil.IntegTest(t)
	di.TestInit(t) // IntegTest doesn't automatically inits DI
	testutil.OnlyEnableCode()

	// this is using the real progress channel, so we need to listen to it
	dummyProgressListeners(t)

	fakeAuthenticationProvider := di.AuthenticationService().Provider().(*vulnmap.FakeAuthenticationProvider)
	fakeAuthenticationProvider.IsAuthenticated = true

	filePath, dir := code.TempWorkdirWithVulnerabilities(t)
	folder := workspace.NewFolder(dir, "dummy", di.Scanner(), di.HoverService(), di.ScanNotifier(), di.Notifier())
	workspace.Set(workspace.New(performance.NewInstrumentor(), di.Scanner(), di.HoverService(), di.ScanNotifier(), di.Notifier()))
	workspace.Get().AddFolder(folder)
	folder.ScanFile(context.Background(), filePath)

	assert.NotNil(t, folder.DocumentDiagnosticsFromCache(filePath))

	lenses := GetFor(filePath)

	assert.NotNil(t, lenses)
	assert.Equal(t, 2, len(lenses))
	assert.Equal(t, code.FakeCommand.CommandId, lenses[0].Command.Command)
	assert.Equal(t, code.FakeFixCommand.CommandId, lenses[1].Command.Command)
}

func dummyProgressListeners(t *testing.T) {
	t.Cleanup(func() { progress.CleanupChannels() })
	go func() {
		for {
			<-progress.Channel
		}
	}()
	go func() {
		for {
			<-progress.CancelProgressChannel
		}
	}()
}
