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

package sentry

import (
	"errors"
	"testing"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/khulnasoft-lab/vulnmap-ls/application/config"
	"github.com/khulnasoft-lab/vulnmap-ls/internal/lsp"
	"github.com/khulnasoft-lab/vulnmap-ls/internal/notification"
	"github.com/khulnasoft-lab/vulnmap-ls/internal/testutil"
	"github.com/khulnasoft-lab/vulnmap-ls/internal/uri"
)

func TestErrorReporting_CaptureError(t *testing.T) {
	testutil.UnitTest(t)
	e := errors.New("test error")
	channel := make(chan sglsp.ShowMessageParams)
	notifier := notification.NewNotifier()
	notifier.CreateListener(func(params any) {
		switch p := params.(type) {
		case sglsp.ShowMessageParams:
			channel <- p
		default:
			log.Debug().Msgf("Unexpected notification: %v", params)
			return
		}
	})
	var target = NewSentryErrorReporter(notifier)

	config.CurrentConfig().SetErrorReportingEnabled(false)
	captured := target.CaptureError(e)
	assert.False(t, captured)

	config.CurrentConfig().SetErrorReportingEnabled(true)
	captured = target.CaptureError(e)
	assert.True(t, captured)

	showMessageParams := <-channel
	assert.Equal(t, "Vulnmap encountered an error: test error", showMessageParams.Message)
}

func TestErrorReporting_CaptureErrorAndReportAsIssue(t *testing.T) {
	testutil.UnitTest(t)
	path := "testPath"
	text := "test error"
	channel := make(chan lsp.PublishDiagnosticsParams)
	notifier := notification.NewNotifier()
	notifier.CreateListener(func(params any) {
		switch p := params.(type) {
		case lsp.PublishDiagnosticsParams:
			channel <- p
		default:
			log.Debug().Msgf("Unexpected notification: %v", params)
			return
		}
	})
	var target = NewSentryErrorReporter(notifier)

	e := errors.New(text)
	config.CurrentConfig().SetErrorReportingEnabled(false)
	captured := target.CaptureErrorAndReportAsIssue(path, e)
	assert.False(t, captured)

	config.CurrentConfig().SetErrorReportingEnabled(true)
	captured = target.CaptureErrorAndReportAsIssue(path, e)
	assert.True(t, captured)

	diagnosticsParams := <-channel
	assert.Equal(t, text, diagnosticsParams.Diagnostics[0].Message)
	assert.Equal(t, lsp.DiagnosticsSeverityWarning, diagnosticsParams.Diagnostics[0].Severity)
	assert.Equal(t, diagnosticsParams.URI, uri.PathToUri(path))
	assert.Equal(t, diagnosticsParams.Diagnostics[0].CodeDescription.Href, lsp.Uri("https://vulnmap.khulnasoft.com/user-hub"))
}
