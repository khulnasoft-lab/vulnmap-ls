package vulnmap_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/khulnasoft-lab/vulnmap-ls/domain/vulnmap"
)

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

var mockCommand = &vulnmap.CommandData{
	Title: "command",
}

var mockDeferredEdit = func() *vulnmap.WorkspaceEdit {
	return mockEdit
}

var mockDeferredCommand = func() *vulnmap.CommandData {
	return mockCommand
}

func Test_NewCodeAction_NoEditOrCommand_Errors(t *testing.T) {

	_, err := vulnmap.NewCodeAction("title", nil, nil)
	assert.Error(t, err)
}

func Test_NewDeferredCodeAction_NoEditOrCommand_Errors(t *testing.T) {

	_, err := vulnmap.NewDeferredCodeAction("title", nil, nil)
	assert.Error(t, err)
}

func Test_NewCodeAction(t *testing.T) {

	action, err := vulnmap.NewCodeAction("title", mockEdit, mockCommand)
	assertActionsInitializedCorrectly(t, err, action, mockEdit, mockCommand, nil, nil)
}

func Test_NewDeferredCodeAction(t *testing.T) {

	action, err := vulnmap.NewDeferredCodeAction("title", &mockDeferredEdit, &mockDeferredCommand)

	assertActionsInitializedCorrectly(t,
		err,
		action,
		(*vulnmap.WorkspaceEdit)(nil),
		(*vulnmap.CommandData)(nil),
		&mockDeferredEdit,
		&mockDeferredCommand)
	assert.NotNil(t, action.Uuid, "UUID should be initialized")
}

func Test_NewPreferredCodeAction(t *testing.T) {

	action, err := vulnmap.NewPreferredCodeAction("title", mockEdit, mockCommand)
	assertActionsInitializedCorrectly(t, err, action, mockEdit, mockCommand, nil, nil)
	assert.True(t, *action.IsPreferred)
}

func assertActionsInitializedCorrectly(t *testing.T,
	err error,
	action vulnmap.CodeAction,
	expectedEdit *vulnmap.WorkspaceEdit,
	expectedCommand *vulnmap.CommandData,
	mockDeferredEdit *func() *vulnmap.WorkspaceEdit,
	mockDeferredCommand *func() *vulnmap.CommandData,
) {
	t.Helper()
	assert.NoError(t, err)
	assert.Equal(t, "title", action.Title)
	assert.Equal(t, expectedEdit, action.Edit)
	assert.Equal(t, expectedCommand, action.Command)
	assert.Equal(t, mockDeferredEdit, action.DeferredEdit)
	assert.Equal(t, mockDeferredCommand, action.DeferredCommand)
}
