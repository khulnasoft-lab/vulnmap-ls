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
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/khulnasoft-lab/vulnmap-ls/application/config"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/ide/notification"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/observability/error_reporting"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/observability/performance"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/vulnmap"
	"github.com/khulnasoft-lab/vulnmap-ls/infrastructure/learn"
	"github.com/khulnasoft-lab/vulnmap-ls/internal/data_structure"
	"github.com/khulnasoft-lab/vulnmap-ls/internal/progress"
	"github.com/khulnasoft-lab/vulnmap-ls/internal/util"
)

type Bundle struct {
	VulnmapCode      VulnmapCodeClient
	BundleHash    string
	UploadBatches []*UploadBatch
	Files         map[string]BundleFile
	instrumentor  performance.Instrumentor
	errorReporter error_reporting.ErrorReporter
	requestId     string
	missingFiles  []string
	limitToFiles  []string
	rootPath      string
	learnService  learn.Service
	notifier      notification.Notifier
}

func (b *Bundle) Upload(ctx context.Context, uploadBatch *UploadBatch) error {
	err := b.extendBundle(ctx, uploadBatch)
	if err != nil {
		return err
	}
	b.UploadBatches = append(b.UploadBatches, uploadBatch)
	return nil
}

func (b *Bundle) extendBundle(ctx context.Context, uploadBatch *UploadBatch) error {
	var removeFiles []string
	var err error
	if uploadBatch.hasContent() {
		b.BundleHash, b.missingFiles, err = b.VulnmapCode.ExtendBundle(ctx, b.BundleHash, uploadBatch.documents, removeFiles)
		log.Debug().Str("requestId", b.requestId).Interface(
			"missingFiles",
			b.missingFiles,
		).Msg("extended bundle on backend")
	}

	return err
}

func (b *Bundle) FetchDiagnosticsData(
	ctx context.Context,
) ([]vulnmap.Issue, error) {
	defer log.Debug().Str("method", "FetchDiagnosticsData").Msg("done.")
	log.Debug().Str("method", "FetchDiagnosticsData").Msg("started.")
	return b.retrieveAnalysis(ctx)
}

func getIssueLangAndRuleId(issue vulnmap.Issue) (string, string, bool) {
	logger := log.With().Str("method", "getIssueLangAndRuleId").Logger()
	issueData, ok := issue.AdditionalData.(vulnmap.CodeIssueData)
	if !ok {
		logger.Trace().Str("file", issue.AffectedFilePath).Int("line", issue.Range.Start.Line).Msg("Can't access issue data")
		return "", "", false
	}
	ruleIdSplit := strings.Split(issueData.RuleId, "/")
	if len(ruleIdSplit) != 2 {
		logger.Trace().Str("file", issue.AffectedFilePath).Int("line", issue.Range.Start.Line).Msg("Issue data does not contain RuleID")
		return "", "", false
	}

	return ruleIdSplit[0], ruleIdSplit[1], true
}

func (b *Bundle) retrieveAnalysis(ctx context.Context) ([]vulnmap.Issue, error) {
	logger := log.With().Str("method", "retrieveAnalysis").Logger()

	if b.BundleHash == "" {
		logger.Warn().Str("rootPath", b.rootPath).Msg("bundle hash is empty")
		return []vulnmap.Issue{}, nil
	}

	p := progress.NewTracker(false)
	p.BeginWithMessage("Vulnmap Code analysis for "+b.rootPath, "Retrieving results...")

	method := "code.retrieveAnalysis"
	s := b.instrumentor.StartSpan(ctx, method)
	defer b.instrumentor.Finish(s)

	analysisOptions := AnalysisOptions{
		bundleHash:   b.BundleHash,
		shardKey:     b.getShardKey(b.rootPath, config.CurrentConfig().Token()),
		limitToFiles: b.limitToFiles,
		severity:     0,
	}

	start := time.Now()
	for {
		if ctx.Err() != nil { // Cancellation requested
			return []vulnmap.Issue{}, nil
		}
		issues, status, err := b.VulnmapCode.RunAnalysis(s.Context(), analysisOptions, b.rootPath)

		if err != nil {
			logger.Error().Err(err).
				Str("requestId", b.requestId).
				Int("fileCount", len(b.UploadBatches)).
				Msg("error retrieving diagnostics...")
			b.errorReporter.CaptureErrorAndReportAsIssue(b.rootPath, err)
			p.EndWithMessage(fmt.Sprintf("Analysis failed: %v", err))
			return []vulnmap.Issue{}, err
		}

		if status.message == completeStatus {
			logger.Trace().Str("requestId", b.requestId).
				Msg("sending diagnostics...")
			p.EndWithMessage("Analysis complete.")

			b.addIssueActions(ctx, issues)

			return issues, nil
		} else if status.message == "ANALYZING" {
			logger.Trace().Msg("\"Analyzing\" message received, sending In-Progress message to client")
		}

		if time.Since(start) > config.CurrentConfig().VulnmapCodeAnalysisTimeout() {
			err := errors.New("analysis call timed out")
			log.Error().Err(err).Msg("timeout...")
			b.errorReporter.CaptureErrorAndReportAsIssue(b.rootPath, err)
			p.EndWithMessage("Vulnmap Code Analysis timed out")
			return []vulnmap.Issue{}, err
		}
		time.Sleep(1 * time.Second)
		p.Report(status.percentage)
	}
}

// Adds code actions and code lenses for issues found
func (b *Bundle) addIssueActions(ctx context.Context, issues []vulnmap.Issue) {
	method := "addCodeActions"

	autoFixEnabled := getCodeSettings().isAutofixEnabled.Get()
	learnEnabled := config.CurrentConfig().IsVulnmapLearnCodeActionsEnabled()
	log.Info().Str("method", method).Msg("Autofix is enabled: " + strconv.FormatBool(autoFixEnabled))
	log.Info().Str("method", method).Msg("Vulnmap Learn is enabled: " + strconv.FormatBool(learnEnabled))

	if !autoFixEnabled && !learnEnabled {
		log.Trace().Msg("Autofix | Vulnmap Learn code actions are disabled, not adding code actions")
		return
	}

	for i := range issues {
		issueData, ok := issues[i].AdditionalData.(vulnmap.CodeIssueData)
		if !ok {
			log.Error().Str("method", method).Msg("Failed to fetch additional data")
			continue
		}

		if autoFixEnabled && issueData.IsAutofixable {
			codeAction := *b.createDeferredAutofixCodeAction(ctx, issues[i])
			issues[i].CodeActions = append(issues[i].CodeActions, codeAction)

			codeActionId := *codeAction.Uuid
			issues[i].CodelensCommands = append(issues[i].CodelensCommands, vulnmap.CommandData{
				Title:     "⚡ Fix this issue: " + issueTitle(issues[i]),
				CommandId: vulnmap.CodeFixCommand,
				Arguments: []any{
					codeActionId,
					issues[i].AffectedFilePath,
					issues[i].Range,
				},
			})
		}

		if learnEnabled {
			action := b.createOpenVulnmapLearnCodeAction(issues[i])
			if action != nil {
				issues[i].CodeActions = append(issues[i].CodeActions, *action)
			}
		}
	}
}

func (b *Bundle) getShardKey(rootPath string, authToken string) string {
	if len(rootPath) > 0 {
		return util.Hash([]byte(rootPath))
	}
	if len(authToken) > 0 {
		return util.Hash([]byte(authToken))
	}

	return ""
}

func (b *Bundle) autofixFunc(ctx context.Context, issue vulnmap.Issue) func() *vulnmap.WorkspaceEdit {
	editFn := func() *vulnmap.WorkspaceEdit {
		method := "code.enhanceWithAutofixSuggestionEdits"
		s := b.instrumentor.StartSpan(ctx, method)
		defer b.instrumentor.Finish(s)

		progress := progress.NewTracker(true)
		fixMsg := "Attempting to fix " + issueTitle(issue) + " (Vulnmap)"
		progress.BeginWithMessage(fixMsg, "")
		b.notifier.SendShowMessage(sglsp.Info, fixMsg)

		relativePath, err := ToRelativeUnixPath(b.rootPath, issue.AffectedFilePath)
		if err != nil {
			log.Error().
				Err(err).Str("method", method).
				Str("rootPath", b.rootPath).
				Str("AffectedFilePath", issue.AffectedFilePath).
				Msg("error converting to relative file path")
			b.notifier.SendShowMessage(sglsp.MTError, "Something went wrong. Please contact Vulnmap support.")
			return nil
		}
		encodedRelativePath := EncodePath(relativePath)

		autofixOptions := AutofixOptions{
			bundleHash: b.BundleHash,
			shardKey:   b.getShardKey(b.rootPath, config.CurrentConfig().Token()),
			filePath:   encodedRelativePath,
			issue:      issue,
		}

		// Polling function just calls the endpoint and registers result, signalling `done` to the
		// channel.
		pollFunc := func() (fix *AutofixSuggestion, complete bool) {
			log.Info().Msg("polling")
			fixSuggestions, fixStatus, err := b.VulnmapCode.RunAutofix(s.Context(), autofixOptions, b.rootPath)
			fix = nil
			complete = false
			if err != nil {
				log.Error().
					Err(err).Str("method", method).Str("requestId", b.requestId).
					Str("stage", "requesting autofix").Msg("error requesting autofix")
				complete = true
			} else if fixStatus.message == completeStatus {
				if len(fixSuggestions) > 0 {
					// TODO(alex.gronskiy): currently, only the first ([0]) fix suggstion goes into the fix
					fix = &fixSuggestions[0]
				} else {
					log.Info().Str("method", method).Str("requestId", b.requestId).Msg("No good fix could be computed.")
				}
				complete = true
			}
			return fix, complete
		}

		// Actual polling loop.
		pollingTicker := time.NewTicker(1 * time.Second)
		defer pollingTicker.Stop()
		timeoutTimer := time.NewTimer(2 * time.Minute)
		defer timeoutTimer.Stop()
		for {
			select {
			case <-timeoutTimer.C:
				log.Error().Str("method", "RunAutofix").Str("requestId", b.requestId).Msg("timeout requesting autofix")
				b.notifier.SendShowMessage(sglsp.MTError, "Something went wrong. Please try again. Request ID: "+b.requestId)
				return nil
			case <-pollingTicker.C:
				fix, complete := pollFunc()
				if !complete {
					continue
				}

				if fix == nil {
					b.notifier.SendShowMessage(sglsp.MTError, "Oh snap! 😔 The fix did not remediate the issue and was not applied.")
					progress.End()
					return nil
				}

				actionCommandMap, err := b.autofixFeedbackActions(fix.FixId)
				successMessage := "Congratulations! 🎉 You’ve just fixed this " + issueTitle(issue) + " issue."
				if err != nil {
					b.notifier.SendShowMessage(sglsp.Info, successMessage)
				} else {
					b.notifier.Send(vulnmap.ShowMessageRequest{
						Message: successMessage + " Was this fix helpful?",
						Type:    vulnmap.Info,
						Actions: actionCommandMap,
					})
				}

				progress.End()
				return &fix.AutofixEdit
			}
		}
	}

	return editFn
}

func (b *Bundle) autofixFeedbackActions(fixId string) (*data_structure.OrderedMap[vulnmap.MessageAction, vulnmap.CommandData], error) {
	createCommandData := func(positive bool) vulnmap.CommandData {
		return vulnmap.CommandData{
			Title:     vulnmap.CodeSubmitFixFeedback,
			CommandId: vulnmap.CodeSubmitFixFeedback,
			Arguments: []any{fixId, positive},
		}
	}
	actionCommandMap := data_structure.NewOrderedMap[vulnmap.MessageAction, vulnmap.CommandData]()
	positiveFeedbackCmd := createCommandData(true)
	negativeFeedbackCmd := createCommandData(false)

	actionCommandMap.Add("👍", positiveFeedbackCmd)
	actionCommandMap.Add("👎", negativeFeedbackCmd)

	return actionCommandMap, nil
}

// returns the deferred code action CodeAction which calls autofix.
func (b *Bundle) createDeferredAutofixCodeAction(ctx context.Context, issue vulnmap.Issue) *vulnmap.CodeAction {
	autofixEditCallback := b.autofixFunc(ctx, issue)

	action, err := vulnmap.NewDeferredCodeAction("⚡ Fix this issue: "+issueTitle(issue)+" (Vulnmap)", &autofixEditCallback, nil)
	if err != nil {
		log.Error().Msg("failed to create deferred autofix code action")
		b.notifier.SendShowMessage(sglsp.MTError, "Something went wrong. Please contact Vulnmap support.")
		return nil
	}
	return &action
}

func (b *Bundle) createOpenVulnmapLearnCodeAction(issue vulnmap.Issue) (ca *vulnmap.CodeAction) {
	title := fmt.Sprintf("Learn more about %s (Vulnmap)", issueTitle(issue))
	lesson, err := b.learnService.GetLesson(issue.Ecosystem, issue.ID, issue.CWEs, issue.CVEs, issue.IssueType)
	if err != nil {
		log.Err(err).Msg("failed to get lesson")
		b.errorReporter.CaptureError(err)
		return nil
	}

	if lesson != nil && lesson.Url != "" {
		ca = &vulnmap.CodeAction{
			Title: title,
			Command: &vulnmap.CommandData{
				Title:     title,
				CommandId: vulnmap.OpenBrowserCommand,
				Arguments: []any{lesson.Url},
			},
		}
	}
	return ca
}

func issueTitle(issue vulnmap.Issue) string {
	if issue.AdditionalData != nil && issue.AdditionalData.(vulnmap.CodeIssueData).Title != "" {
		return issue.AdditionalData.(vulnmap.CodeIssueData).Title
	}

	return issue.ID
}
