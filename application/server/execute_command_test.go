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

package server

import (
	"context"
	"testing"
	"time"

	"github.com/atotto/clipboard"
	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/khulnasoft-lab/vulnmap-ls/application/config"
	"github.com/khulnasoft-lab/vulnmap-ls/application/di"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/ide/command"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/ide/workspace"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/vulnmap"
)

func Test_executeWorkspaceScanCommand_shouldStartWorkspaceScanOnCommandReceipt(t *testing.T) {
	loc := setupServerWithCustomDI(t, false)

	scanner := &vulnmap.TestScanner{}
	workspace.Get().AddFolder(workspace.NewFolder("dummy", "dummy", scanner, di.HoverService(), di.ScanNotifier(), di.Notifier()))

	params := lsp.ExecuteCommandParams{Command: vulnmap.WorkspaceScanCommand}
	_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
	if err != nil {
		t.Fatal(err)
	}
	assert.Eventually(t, func() bool {
		return scanner.Calls() > 0
	}, 2*time.Second, time.Millisecond)
}

func Test_executeWorkspaceFolderScanCommand_shouldStartFolderScanOnCommandReceipt(t *testing.T) {
	loc := setupServerWithCustomDI(t, false)

	scanner := &vulnmap.TestScanner{}
	workspace.Get().AddFolder(workspace.NewFolder("dummy", "dummy", scanner, di.HoverService(), di.ScanNotifier(), di.Notifier()))

	params := lsp.ExecuteCommandParams{Command: vulnmap.WorkspaceFolderScanCommand, Arguments: []any{"dummy"}}
	_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
	if err != nil {
		t.Fatal(err)
	}
	assert.Eventually(t, func() bool {
		return scanner.Calls() > 0
	}, 2*time.Second, time.Millisecond)
}

func Test_executeWorkspaceFolderScanCommand_shouldNotClearOtherFoldersDiagnostics(t *testing.T) {
	loc := setupServerWithCustomDI(t, false)

	scannerForFolder := vulnmap.NewTestScanner()
	scannerForDontClear := vulnmap.NewTestScanner()
	folder := workspace.NewFolder("dummy", "dummy", scannerForFolder, di.HoverService(), di.ScanNotifier(), di.Notifier())
	dontClear := workspace.NewFolder("dontclear", "dontclear", scannerForDontClear, di.HoverService(), di.ScanNotifier(), di.Notifier())

	dontClearIssuePath := "dontclear/file.txt"
	scannerForDontClear.AddTestIssue(vulnmap.Issue{AffectedFilePath: dontClearIssuePath})
	scannerForFolder.AddTestIssue(vulnmap.Issue{AffectedFilePath: "dummy/file.txt"})

	workspace.Get().AddFolder(folder)
	workspace.Get().AddFolder(dontClear)

	// prepare pre-existent diagnostics for folder
	folder.ScanFolder(context.Background())
	dontClear.ScanFolder(context.Background())

	params := lsp.ExecuteCommandParams{Command: vulnmap.WorkspaceFolderScanCommand, Arguments: []any{"dummy"}}
	_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
	if err != nil {
		t.Fatal(err)
	}
	assert.Eventually(t, func() bool {
		// must be two scans for dummy as initialization + scan after issuing command
		return scannerForFolder.Calls() == 2 && scannerForDontClear.Calls() == 1
	}, 2*time.Second, time.Millisecond)

	assert.Equal(t, 1, len(dontClear.AllIssuesFor(dontClearIssuePath)))
}

func Test_executeWorkspaceScanCommand_shouldAskForTrust(t *testing.T) {
	loc := setupServerWithCustomDI(t, false)

	scanner := &vulnmap.TestScanner{}
	workspace.Get().AddFolder(workspace.NewFolder("dummy", "dummy", scanner, di.HoverService(), di.ScanNotifier(), di.Notifier()))
	// explicitly enable folder trust which is disabled by default in tests
	config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)

	params := lsp.ExecuteCommandParams{Command: vulnmap.WorkspaceScanCommand}
	_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
	if err != nil {
		t.Fatal(err)
	}
	assert.Eventually(t, func() bool {
		return scanner.Calls() == 0 && checkTrustMessageRequest()
	}, 2*time.Second, time.Millisecond)
}

func Test_loginCommand_StartsAuthentication(t *testing.T) {
	// Arrange
	loc := setupServer(t)

	// reset to use real service
	command.SetService(command.NewService(di.AuthenticationService(), nil, nil, nil, nil))

	config.CurrentConfig().SetAutomaticAuthentication(false)
	_, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	fakeAuthenticationProvider := di.AuthenticationService().Provider().(*vulnmap.FakeAuthenticationProvider)
	fakeAuthenticationProvider.IsAuthenticated = false
	params := lsp.ExecuteCommandParams{Command: vulnmap.LoginCommand}

	// Act
	_, err = loc.Client.Call(ctx, "workspace/executeCommand", params)
	if err != nil {
		t.Fatal(err)
	}

	// Assert
	assert.True(t, fakeAuthenticationProvider.IsAuthenticated)
	assert.Eventually(t, func() bool { return len(jsonRPCRecorder.Notifications()) > 0 }, 5*time.Second, 50*time.Millisecond)
	assert.Equal(t, 1, len(jsonRPCRecorder.FindNotificationsByMethod("$/vulnmap.hasAuthenticated")))
}

func Test_executeCommand_shouldCopyAuthURLToClipboard(t *testing.T) {
	t.Skip("This test uses global state (the clipboard) and is thus not reliable")
	loc := setupServer(t)

	// reset to use real service
	command.SetService(command.NewService(di.AuthenticationService(), nil, nil, nil, nil))

	authenticationMock := di.AuthenticationService().Provider().(*vulnmap.FakeAuthenticationProvider)
	params := lsp.ExecuteCommandParams{Command: vulnmap.CopyAuthLinkCommand}

	_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
	if err != nil {
		t.Fatal(err)
	}
	actualURL, _ := clipboard.ReadAll()

	assert.Equal(t, authenticationMock.ExpectedAuthURL, actualURL)
}

func Test_TrustWorkspaceFolders(t *testing.T) {
	t.Run("Doesn't mutate trusted folders, if trusted folders disabled", func(t *testing.T) {
		loc := setupServerWithCustomDI(t, false)
		workspace.Get().AddFolder(workspace.NewFolder("/path/to/folder1", "dummy", nil, di.HoverService(), di.ScanNotifier(), di.Notifier()))

		params := lsp.ExecuteCommandParams{Command: vulnmap.TrustWorkspaceFoldersCommand}
		_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
		if err != nil {
			t.Fatal(err)
		}

		assert.Len(t, config.CurrentConfig().TrustedFolders(), 0)
	})

	t.Run("Updates trusted workspace folders", func(t *testing.T) {
		loc := setupServerWithCustomDI(t, false)

		workspace.Get().AddFolder(workspace.NewFolder("/path/to/folder1", "dummy", nil, di.HoverService(), di.ScanNotifier(), di.Notifier()))
		workspace.Get().AddFolder(workspace.NewFolder("/path/to/folder2", "dummy", nil, di.HoverService(), di.ScanNotifier(), di.Notifier()))
		config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)

		params := lsp.ExecuteCommandParams{Command: vulnmap.TrustWorkspaceFoldersCommand}
		_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
		if err != nil {
			t.Fatal(err)
		}

		assert.Len(t, config.CurrentConfig().TrustedFolders(), 2)
		assert.Contains(t, config.CurrentConfig().TrustedFolders(), "/path/to/folder1", "/path/to/folder2")
	})

	t.Run("Existing trusted workspace folders are not removed", func(t *testing.T) {
		loc := setupServerWithCustomDI(t, false)

		workspace.Get().AddFolder(workspace.NewFolder("/path/to/folder1", "dummy", nil, di.HoverService(), di.ScanNotifier(), di.Notifier()))
		config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)
		config.CurrentConfig().SetTrustedFolders([]string{"/path/to/folder2"})

		params := lsp.ExecuteCommandParams{Command: vulnmap.TrustWorkspaceFoldersCommand}
		_, err := loc.Client.Call(ctx, "workspace/executeCommand", params)
		if err != nil {
			t.Fatal(err)
		}

		assert.Len(t, config.CurrentConfig().TrustedFolders(), 2)
		assert.Contains(t, config.CurrentConfig().TrustedFolders(), "/path/to/folder1", "/path/to/folder2")
	})
}
