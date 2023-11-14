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
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/khulnasoft-lab/vulnmap-ls/application/config"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/ide/converter"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/vulnmap"
	"github.com/khulnasoft-lab/vulnmap-ls/internal/lsp"
	"github.com/khulnasoft-lab/vulnmap-ls/internal/notification"
	"github.com/khulnasoft-lab/vulnmap-ls/internal/product"
	"github.com/khulnasoft-lab/vulnmap-ls/internal/testutil"
)

var sampleRangeArg = map[string]interface{}{
	"Start": map[string]interface{}{
		"Line":      float64(1),
		"Character": float64(1),
	},
	"End": map[string]interface{}{
		"Line":      float64(1),
		"Character": float64(10),
	},
}
var codeActionId = uuid.New()
var sampleArgs = []any{codeActionId.String(), "test/path.js", sampleRangeArg}

type issueProviderMock struct {
	mock.Mock
}

func (m *issueProviderMock) IssuesFor(path string, r vulnmap.Range) []vulnmap.Issue {
	args := m.Called(path, r)
	return args.Get(0).([]vulnmap.Issue)
}

func setupClientCapability(config *config.Config) {
	clientCapabilties := config.ClientCapabilities()
	clientCapabilties.Workspace.ApplyEdit = true
	config.SetClientCapabilities(clientCapabilties)
}

func setupCommand(mockNotifier *notification.MockNotifier) *fixCodeIssue {
	cmdData := vulnmap.CommandData{
		CommandId: vulnmap.CodeFixCommand,
		Arguments: sampleArgs,
	}
	cmd := &fixCodeIssue{
		command:  cmdData,
		notifier: mockNotifier,
	}
	return cmd
}

func setupMockEdit() (edit *vulnmap.WorkspaceEdit, deferredEdit func() *vulnmap.WorkspaceEdit) {
	var mockTextEdit = vulnmap.TextEdit{
		Range: vulnmap.Range{
			Start: vulnmap.Position{Line: 1, Character: 2},
			End:   vulnmap.Position{Line: 3, Character: 4}},
		NewText: "someText",
	}
	var mockEdit = &vulnmap.WorkspaceEdit{
		Changes: map[string][]vulnmap.TextEdit{
			"someUri": {mockTextEdit},
		},
	}
	var deferredMockEdit = func() *vulnmap.WorkspaceEdit {
		return mockEdit
	}
	return mockEdit, deferredMockEdit
}

func setupSampleIssues(issueRange vulnmap.Range, codeAction vulnmap.CodeAction, cmdData vulnmap.CommandData) []vulnmap.Issue {
	return []vulnmap.Issue{{
		ID:          "VULNMAP-123",
		Range:       issueRange,
		Severity:    vulnmap.High,
		Product:     product.ProductCode,
		IssueType:   vulnmap.CodeSecurityVulnerability,
		Message:     "This is a dummy error (severity error)",
		CodeActions: []vulnmap.CodeAction{codeAction},
		CodelensCommands: []vulnmap.CommandData{
			cmdData,
		},
	}}
}

func Test_fixCodeIssue_ErrorsWhenNoCapability(t *testing.T) {
	testutil.UnitTest(t)
	cmd := &fixCodeIssue{
		command: vulnmap.CommandData{
			CommandId: vulnmap.CodeFixCommand,
			Arguments: []any{sampleArgs},
		},
	}

	_, err := cmd.Execute(context.Background())

	assert.Error(t, err)
	assert.ErrorContains(t, err, "Client doesn't support 'workspace/applyEdit' capability.")
}

func Test_fixCodeIssue_sendsSuccessfulEdit(t *testing.T) {
	config := testutil.UnitTest(t)
	// arrange
	setupClientCapability(config)

	mockNotifier := notification.NewMockNotifier()
	cmd := setupCommand(mockNotifier)

	filePath := sampleArgs[1]
	issueRange := cmd.toRange(sampleArgs[2])
	mockEdit, deferredMockEdit := setupMockEdit()
	codeAction := vulnmap.CodeAction{
		Uuid:         &codeActionId,
		DeferredEdit: &deferredMockEdit,
	}
	issues := setupSampleIssues(issueRange, codeAction, cmd.command)

	issueProviderMock := new(issueProviderMock)
	issueProviderMock.On("IssuesFor", filePath, issueRange).Return(issues)
	cmd.issueProvider = issueProviderMock

	// act
	res, err := cmd.Execute(context.Background())

	// assert
	assert.NoError(t, err)
	assert.Nil(t, res)
	assert.Nil(t, issues[0].CodelensCommands) // verify commands are reset

	// Verify workspace edit is sent to the client
	workspaceEdit := converter.ToWorkspaceEdit(mockEdit)
	assert.Equal(t, []any{lsp.ApplyWorkspaceEditParams{Label: "Vulnmap Code fix", Edit: workspaceEdit}, lsp.CodeLensRefresh{}}, mockNotifier.SentMessages())
}

func Test_fixCodeIssue_noEdit(t *testing.T) {
	config := testutil.UnitTest(t)
	// arrange
	setupClientCapability(config)

	mockNotifier := notification.NewMockNotifier()
	cmd := setupCommand(mockNotifier)

	filePath := sampleArgs[1]
	issueRange := cmd.toRange(sampleArgs[2])
	deferredMockEdit := func() *vulnmap.WorkspaceEdit {
		return nil
	}
	codeAction := vulnmap.CodeAction{
		Uuid:         &codeActionId,
		DeferredEdit: &deferredMockEdit,
	}
	issues := setupSampleIssues(issueRange, codeAction, cmd.command)

	issueProviderMock := new(issueProviderMock)
	issueProviderMock.On("IssuesFor", filePath, issueRange).Return(issues)
	cmd.issueProvider = issueProviderMock

	// act
	res, err := cmd.Execute(context.Background())

	// assert
	assert.NoError(t, err)
	assert.Nil(t, res)
	assert.NotNil(t, issues[0].CodelensCommands) // verify commands isn't reset

	var sentMessages []any
	// Verify no workspace edit is sent to the client
	assert.Equal(t, sentMessages, mockNotifier.SentMessages())
}

func Test_fixCodeIssue_NoIssueFound(t *testing.T) {
	config := testutil.UnitTest(t)
	// arrange
	setupClientCapability(config)

	mockNotifier := notification.NewMockNotifier()
	cmd := setupCommand(mockNotifier)

	filePath := sampleArgs[1]
	issueRange := cmd.toRange(sampleArgs[2])

	issueProviderMock := new(issueProviderMock)
	issueProviderMock.On("IssuesFor", filePath, issueRange).Return([]vulnmap.Issue{})
	cmd.issueProvider = issueProviderMock

	// act
	res, err := cmd.Execute(context.Background())

	// assert
	assert.Error(t, err)
	assert.ErrorContains(t, err, "Failed to find autofix code action.")
	assert.Nil(t, res)

	var expectedMsg []any
	// Verify no workspace edit is sent to the client
	assert.Equal(t, expectedMsg, mockNotifier.SentMessages())
}
