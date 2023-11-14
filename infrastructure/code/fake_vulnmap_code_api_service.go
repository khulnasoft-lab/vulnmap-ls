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

package code

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"

	"github.com/khulnasoft-lab/vulnmap-ls/domain/vulnmap"
	"github.com/khulnasoft-lab/vulnmap-ls/internal/product"
	"github.com/khulnasoft-lab/vulnmap-ls/internal/util"
)

const (
	CreateBundleOperation           = "createBundle"
	ExtendBundleWithSourceOperation = "extendBundleWithSource"
	RunAnalysisOperation            = "runAnalysis"
	RunAutofixOperation             = "runAutofix"
	GetFiltersOperation             = "getFilters"
	FakeFileExtension               = ".java"
	// Helper constants to synchronize fake results and tests
	FakeAutofixSuggestionNewText = "FAKE_AUTOFIX_NEW_TEXT"
)

var (
	FakeVulnmapCodeApiServiceMutex = &sync.Mutex{}

	fakeRange = vulnmap.Range{
		Start: vulnmap.Position{
			Line:      0,
			Character: 3,
		},
		End: vulnmap.Position{
			Line:      0,
			Character: 7,
		},
	}
	FakeCommand = vulnmap.CommandData{
		Title:     "Code Flow blah blah fake",
		CommandId: vulnmap.NavigateToRangeCommand,
		Arguments: []any{"path", fakeRange},
	}
	FakeFixCommand = vulnmap.CommandData{
		Title:     "Code Flow blah blah fake",
		CommandId: vulnmap.CodeFixCommand,
		Arguments: []any{"id", "path", fakeRange},
	}

	FakeIssue = vulnmap.Issue{
		ID:               "VULNMAP-123",
		Range:            fakeRange,
		Severity:         vulnmap.High,
		Product:          product.ProductCode,
		IssueType:        vulnmap.CodeQualityIssue,
		Message:          "This is a dummy error (severity error)",
		CodelensCommands: []vulnmap.CommandData{FakeCommand, FakeFixCommand},
		CodeActions:      []vulnmap.CodeAction{FakeCodeAction},
		AdditionalData: vulnmap.CodeIssueData{
			IsAutofixable: true,
		},
	}

	FakeCodeAction = vulnmap.CodeAction{
		Title:   "FakeAction",
		Command: &FakeCommand,
	}

	FakeFilters        = []string{".cjs", ".ejs", ".es", ".es6", ".htm", ".html", ".js", ".jsx", ".mjs", ".ts", ".tsx", ".vue", ".java", ".erb", ".haml", ".rb", ".rhtml", ".slim", ".kt", ".swift", ".cls", ".config", ".pom", ".wxs", ".xml", ".xsd", ".aspx", ".cs", ".py", ".go", ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx", ".php", ".phtml"}
	FakeAutofixFilters = []string{FakeFileExtension} // Main test scenario -- allowlist the fake file for autofix
)

func TempWorkdirWithVulnerabilities(t *testing.T) (filePath string, path string) {
	FakeVulnmapCodeApiServiceMutex.Lock()
	defer FakeVulnmapCodeApiServiceMutex.Unlock()

	temp := t.TempDir()
	temp = filepath.Clean(temp)
	temp, err := filepath.Abs(temp)
	if err != nil {
		t.Fatal(err, "couldn't get abs path of tempdir")
	}

	filePath = filepath.Join(temp, "Dummy"+FakeFileExtension)
	classWithQualityIssue := "public class AnnotatorTest {\n  public static void delay(long millis) {\n    try {\n      Thread.sleep(millis);\n    } catch (InterruptedException e) {\n      e.printStackTrace();\n    }\n  }\n};"
	err = os.WriteFile(filePath, []byte(classWithQualityIssue), 0600)
	if err != nil {
		t.Fatal(err, "couldn't create temp file for fake diagnostic")
	}
	FakeIssue.AffectedFilePath = filePath
	return filePath, temp
}

type FakeVulnmapCodeClient struct {
	Calls                  map[string][][]any
	HasCreatedNewBundle    bool
	HasExtendedBundle      bool
	ExtendBundleFiles      map[string]BundleFile
	TotalBundleCount       int
	ExtendedBundleCount    int
	AnalysisDuration       time.Duration
	FailOnCreateBundle     bool
	ConfigFiles            []string
	currentConcurrentScans int
	maxConcurrentScans     int
	NoFixSuggestions       bool
}

func (f *FakeVulnmapCodeClient) addCall(params []any, op string) {
	if f.Calls == nil {
		f.Calls = make(map[string][][]any)
	}
	calls := f.Calls[op]
	var opParams []any
	opParams = append(opParams, params...)
	f.Calls[op] = append(calls, opParams)
}

func (f *FakeVulnmapCodeClient) GetCallParams(callNo int, op string) []any {
	FakeVulnmapCodeApiServiceMutex.Lock()
	defer FakeVulnmapCodeApiServiceMutex.Unlock()
	calls := f.Calls[op]
	if calls == nil {
		return nil
	}
	params := calls[callNo]
	if params == nil {
		return nil
	}
	return params
}

func (f *FakeVulnmapCodeClient) Clear() {
	FakeVulnmapCodeApiServiceMutex.Lock()
	defer FakeVulnmapCodeApiServiceMutex.Unlock()
	f.ExtendedBundleCount = 0
	f.TotalBundleCount = 0
	f.HasExtendedBundle = false
}

func (f *FakeVulnmapCodeClient) GetAllCalls(op string) [][]any {
	FakeVulnmapCodeApiServiceMutex.Lock()
	defer FakeVulnmapCodeApiServiceMutex.Unlock()
	calls := f.Calls[op]
	if calls == nil {
		return nil
	}
	return calls
}

func (f *FakeVulnmapCodeClient) GetFilters(_ context.Context) (
	filters FiltersResponse,
	err error,
) {
	FakeVulnmapCodeApiServiceMutex.Lock()
	defer FakeVulnmapCodeApiServiceMutex.Unlock()
	params := []any{filters.ConfigFiles,
		filters.Extensions,
		err}
	f.addCall(params, GetFiltersOperation)
	return FiltersResponse{ConfigFiles: f.ConfigFiles,
		Extensions: FakeFilters,
	}, nil
}

func (f *FakeVulnmapCodeClient) CreateBundle(_ context.Context,
	files map[string]string,
) (bundleHash string, missingFiles []string, err error) {
	if f.FailOnCreateBundle {
		return "", nil, errors.New("Mock Code client failed intentionally on CreateBundle")
	}

	FakeVulnmapCodeApiServiceMutex.Lock()
	defer FakeVulnmapCodeApiServiceMutex.Unlock()
	f.TotalBundleCount++
	f.HasCreatedNewBundle = true
	params := []any{files}
	f.addCall(params, CreateBundleOperation)
	for filePath := range files {
		missingFiles = append(missingFiles, filePath)
	}
	return util.Hash([]byte(fmt.Sprint(rand.Int()))), missingFiles, nil
}

func (f *FakeVulnmapCodeClient) ExtendBundle(
	_ context.Context,
	bundleHash string,
	files map[string]BundleFile,
	removedFiles []string,
) (string, []string, error) {
	FakeVulnmapCodeApiServiceMutex.Lock()
	defer FakeVulnmapCodeApiServiceMutex.Unlock()
	f.HasExtendedBundle = true
	f.TotalBundleCount++
	f.ExtendedBundleCount++
	f.ExtendBundleFiles = files
	params := []any{bundleHash, files, removedFiles}
	f.addCall(params, ExtendBundleWithSourceOperation)
	return util.Hash([]byte(fmt.Sprint(rand.Int()))), nil, nil
}

var successfulResult = AnalysisStatus{
	message:    "COMPLETE",
	percentage: 100,
}

func (f *FakeVulnmapCodeClient) RunAnalysis(
	_ context.Context,
	options AnalysisOptions,
	_ string,
) ([]vulnmap.Issue, AnalysisStatus, error) {

	FakeVulnmapCodeApiServiceMutex.Lock()
	f.currentConcurrentScans++
	if f.currentConcurrentScans > f.maxConcurrentScans {
		f.maxConcurrentScans = f.currentConcurrentScans
	}
	FakeVulnmapCodeApiServiceMutex.Unlock()
	<-time.After(f.AnalysisDuration)
	FakeVulnmapCodeApiServiceMutex.Lock()
	f.currentConcurrentScans--
	params := []any{options.bundleHash, options.limitToFiles, options.severity}
	f.addCall(params, RunAnalysisOperation)
	FakeVulnmapCodeApiServiceMutex.Unlock()

	issues := []vulnmap.Issue{FakeIssue}
	if f.NoFixSuggestions {
		if issueData, ok := issues[0].AdditionalData.(vulnmap.CodeIssueData); ok {
			issueData.IsAutofixable = false
			issues[0].AdditionalData = issueData
		}
	}

	log.Trace().Str("method", "RunAnalysis").Interface(
		"fakeDiagnostic",
		FakeIssue,
	).Msg("fake backend call received & answered")
	return issues, successfulResult, nil
}

func (f *FakeVulnmapCodeClient) RunAutofix(
	_ context.Context,
	options AutofixOptions,
	baseDir string,
) ([]AutofixSuggestion, AutofixStatus, error) {
	<-time.After(f.AnalysisDuration)
	FakeVulnmapCodeApiServiceMutex.Lock()
	params := []any{options.bundleHash, options.filePath, options.issue.ID, options.issue.Range.Start.Line}
	f.addCall(params, RunAutofixOperation)
	FakeVulnmapCodeApiServiceMutex.Unlock()

	if f.NoFixSuggestions {
		log.Trace().Str("method", "RunAutofix").Interface("fakeAutofix",
			"someAutofixSuggestion").Msg("fake backend call received & answered with no suggestions")
		return nil, AutofixStatus{message: "COMPLETE"}, nil
	}

	suggestions := []AutofixSuggestion{
		// First suggestion
		{
			FixId: "123e4567-e89b-12d3-a456-426614174000/1",
			AutofixEdit: vulnmap.WorkspaceEdit{
				Changes: map[string][]vulnmap.TextEdit{
					options.filePath: {vulnmap.TextEdit{
						Range: vulnmap.Range{
							Start: vulnmap.Position{Line: 0, Character: 0},
							End:   vulnmap.Position{Line: 10000, Character: 0},
						},
						NewText: FakeAutofixSuggestionNewText,
					}},
				},
			},
		},
		// Second suggestion -- currently dropped
		{
			FixId: "123e4567-e89b-12d3-a456-426614174000/2",
			AutofixEdit: vulnmap.WorkspaceEdit{
				Changes: map[string][]vulnmap.TextEdit{
					options.filePath: {vulnmap.TextEdit{
						Range: vulnmap.Range{
							Start: vulnmap.Position{Line: 0, Character: 0},
							End:   vulnmap.Position{Line: 10000, Character: 0},
						},
						NewText: "FAKE_AUTOFIX_UNUSED",
					}},
				},
			},
		},
	}

	log.Trace().Str("method", "RunAutofix").Interface("fakeAutofix",
		"someAutofixSuggestion").Msg("fake backend call received & answered")
	return suggestions, AutofixStatus{message: "COMPLETE"}, nil
}

func (f *FakeVulnmapCodeClient) SubmitAutofixFeedback(ctx context.Context, fixId string, positive bool) error {
	return nil
}
