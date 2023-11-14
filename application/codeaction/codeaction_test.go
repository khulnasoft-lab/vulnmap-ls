package codeaction_test

import (
	"testing"

	"github.com/google/uuid"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/khulnasoft-lab/vulnmap-ls/application/codeaction"
	"github.com/khulnasoft-lab/vulnmap-ls/application/config"
	"github.com/khulnasoft-lab/vulnmap-ls/application/watcher"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/ide/command"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/ide/converter"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/vulnmap"
	"github.com/khulnasoft-lab/vulnmap-ls/infrastructure/code"
	"github.com/khulnasoft-lab/vulnmap-ls/internal/lsp"
	"github.com/khulnasoft-lab/vulnmap-ls/internal/notification"
	"github.com/khulnasoft-lab/vulnmap-ls/internal/testutil"
	"github.com/khulnasoft-lab/vulnmap-ls/internal/uri"
)

type mockIssuesProvider struct {
	mock.Mock
}

func (m *mockIssuesProvider) IssuesFor(path string, r vulnmap.Range) []vulnmap.Issue {
	args := m.Called(path, r)
	return args.Get(0).([]vulnmap.Issue)
}

var exampleRange = sglsp.Range{
	Start: sglsp.Position{
		Line:      10,
		Character: 0,
	},
	End: sglsp.Position{
		Line:      10,
		Character: 8,
	},
}

const documentUriExample = sglsp.DocumentURI("file:///path/to/file")

func Test_GetCodeActions_ReturnsCorrectActions(t *testing.T) {
	testutil.UnitTest(t)
	expectedIssue := vulnmap.Issue{
		CodeActions: []vulnmap.CodeAction{
			{
				Title:   "Fix this",
				Command: &code.FakeCommand,
			},
		},
	}
	service, codeActionsParam, _ := setupWithSingleIssue(expectedIssue)

	// Act
	actions := service.GetCodeActions(codeActionsParam)

	// Assert
	assert.Len(t, actions, 1)
	assert.Equal(t, expectedIssue.CodeActions[0].Command.CommandId, actions[0].Command.Command)
}

func Test_GetCodeActions_FileIsDirty_ReturnsEmptyResults(t *testing.T) {
	testutil.UnitTest(t)
	fakeIssue := vulnmap.Issue{
		CodeActions: []vulnmap.CodeAction{
			{
				Title:   "Fix this",
				Command: &code.FakeCommand,
			},
		},
	}
	service, codeActionsParam, w := setupWithSingleIssue(fakeIssue)
	w.SetFileAsChanged(codeActionsParam.TextDocument.URI) // File is dirty until it is saved

	// Act
	actions := service.GetCodeActions(codeActionsParam)

	// Assert
	assert.Empty(t, actions)
}

func Test_GetCodeActions_NoIssues_ReturnsNil(t *testing.T) {
	testutil.UnitTest(t)
	// It doesn't seem like there's a difference between returning a nil and returning an empty array. If this assumption
	// is proved to be false, this test can be changed.
	// Arrange

	var issues []vulnmap.Issue
	providerMock := new(mockIssuesProvider)
	providerMock.On("IssuesFor", mock.Anything, mock.Anything).Return(issues)
	fakeClient := &code.FakeVulnmapCodeClient{}
	vulnmapCodeClient := fakeClient
	service := codeaction.NewService(config.CurrentConfig(), providerMock, watcher.NewFileWatcher(), notification.NewNotifier(), vulnmapCodeClient)
	codeActionsParam := lsp.CodeActionParams{
		TextDocument: sglsp.TextDocumentIdentifier{
			URI: documentUriExample,
		},
		Range:   exampleRange,
		Context: lsp.CodeActionContext{},
	}

	// Act
	actions := service.GetCodeActions(codeActionsParam)

	// Assert
	assert.Nil(t, actions)
}

func Test_ResolveCodeAction_ReturnsCorrectEdit(t *testing.T) {
	testutil.UnitTest(t)
	// Arrange

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
	deferredEdit := func() *vulnmap.WorkspaceEdit {
		return mockEdit
	}
	id := uuid.New()
	expectedIssue := vulnmap.Issue{
		CodeActions: []vulnmap.CodeAction{
			{
				Title:        "Fix this",
				DeferredEdit: &deferredEdit,
				Uuid:         &id,
			},
		},
	}
	service, codeActionsParam, _ := setupWithSingleIssue(expectedIssue)

	// Act
	actions := service.GetCodeActions(codeActionsParam)
	actionFromRequest := actions[0]
	resolvedAction, _ := service.ResolveCodeAction(actionFromRequest, nil, nil, nil)

	// Assert
	assert.NotNil(t, resolvedAction)
	assert.Equal(t, lsp.CodeActionData(id), *resolvedAction.Data)
	assert.Nil(t, actionFromRequest.Edit)
	assert.Nil(t, actionFromRequest.Command)
	assert.NotNil(t, resolvedAction.Edit)
}

func Test_ResolveCodeAction_KeyDoesNotExist_ReturnError(t *testing.T) {
	testutil.UnitTest(t)
	// Arrange
	service := setupService()

	id := lsp.CodeActionData(uuid.New())
	ca := lsp.CodeAction{
		Title:   "Made up CA",
		Edit:    nil,
		Command: nil,
		Data:    &id,
	}

	// Act
	var err error
	_, err = service.ResolveCodeAction(ca, nil, nil, nil)

	// Assert
	assert.Error(t, err, "Expected error when resolving a code action with a key that doesn't exist")
}

func Test_ResolveCodeAction_UnknownCommandIsReported(t *testing.T) {
	testutil.UnitTest(t)
	// Arrange
	service := setupService()
	command.SetService(command.NewService(nil, nil, nil, nil, nil))

	id := lsp.CodeActionData(uuid.New())
	c := &sglsp.Command{
		Title:     "test",
		Command:   "test",
		Arguments: []any{"test"},
	}
	ca := lsp.CodeAction{
		Title:   "Made up CA",
		Edit:    nil,
		Command: c,
		Data:    &id,
	}

	// Act
	var err error
	_, err = service.ResolveCodeAction(ca, nil, nil, nil)

	// Assert
	assert.Error(t, err, "Command factory should have been called with fake command and returned not found err")
	assert.Contains(t, err.Error(), "unknown command")
}

func Test_ResolveCodeAction_CommandIsExecuted(t *testing.T) {
	testutil.UnitTest(t)
	// Arrange
	service := setupService()

	id := lsp.CodeActionData(uuid.New())
	command.SetService(vulnmap.NewCommandServiceMock())

	c := &sglsp.Command{
		Title:   vulnmap.LoginCommand,
		Command: vulnmap.LoginCommand,
	}
	ca := lsp.CodeAction{
		Title:   "Made up CA",
		Edit:    nil,
		Command: c,
		Data:    &id,
	}

	_, err := service.ResolveCodeAction(ca, nil, nil, nil)
	assert.NoError(t, err, "command should be called without error")

	serviceMock := command.Service().(*vulnmap.CommandServiceMock)
	assert.Len(t, serviceMock.ExecutedCommands(), 1)
	assert.Equal(t, serviceMock.ExecutedCommands()[0].CommandId, c.Command)
}

func Test_ResolveCodeAction_KeyIsNull_ReturnsError(t *testing.T) {
	testutil.UnitTest(t)
	service := setupService()

	ca := lsp.CodeAction{
		Title:   "Made up CA",
		Edit:    nil,
		Command: nil,
		Data:    nil,
	}

	_, err := service.ResolveCodeAction(ca, nil, nil, nil)
	assert.Error(t, err, "Expected error when resolving a code action with a null key")
	assert.True(t, codeaction.IsMissingKeyError(err))
}

func setupService() *codeaction.CodeActionsService {
	providerMock := new(mockIssuesProvider)
	providerMock.On("IssuesFor", mock.Anything, mock.Anything).Return([]vulnmap.Issue{})
	fakeClient := &code.FakeVulnmapCodeClient{}
	vulnmapCodeClient := fakeClient
	service := codeaction.NewService(config.CurrentConfig(), providerMock, watcher.NewFileWatcher(), notification.NewNotifier(), vulnmapCodeClient)
	return service
}

func setupWithSingleIssue(issue vulnmap.Issue) (*codeaction.CodeActionsService, lsp.CodeActionParams, *watcher.FileWatcher) {
	r := exampleRange
	uriPath := documentUriExample
	path := uri.PathFromUri(uriPath)
	providerMock := new(mockIssuesProvider)
	issues := []vulnmap.Issue{issue}
	providerMock.On("IssuesFor", path, converter.FromRange(r)).Return(issues)
	fileWatcher := watcher.NewFileWatcher()
	fakeClient := &code.FakeVulnmapCodeClient{}
	vulnmapCodeClient := fakeClient
	service := codeaction.NewService(config.CurrentConfig(), providerMock, fileWatcher, notification.NewNotifier(), vulnmapCodeClient)

	codeActionsParam := lsp.CodeActionParams{
		TextDocument: sglsp.TextDocumentIdentifier{
			URI: uriPath,
		},
		Range:   r,
		Context: lsp.CodeActionContext{},
	}
	return service, codeActionsParam, fileWatcher
}
