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

package di

import (
	"testing"

	"github.com/golang/mock/gomock"

	"github.com/khulnasoft-lab/vulnmap-ls/application/codeaction"
	"github.com/khulnasoft-lab/vulnmap-ls/application/config"
	appNotification "github.com/khulnasoft-lab/vulnmap-ls/application/server/notification"
	"github.com/khulnasoft-lab/vulnmap-ls/application/watcher"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/ide/command"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/ide/hover"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/ide/initialize"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/ide/workspace"
	er "github.com/khulnasoft-lab/vulnmap-ls/domain/observability/error_reporting"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/observability/performance"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/observability/ux"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/vulnmap"
	"github.com/khulnasoft-lab/vulnmap-ls/infrastructure/cli"
	cliauth "github.com/khulnasoft-lab/vulnmap-ls/infrastructure/cli/auth"
	"github.com/khulnasoft-lab/vulnmap-ls/infrastructure/cli/install"
	"github.com/khulnasoft-lab/vulnmap-ls/infrastructure/code"
	"github.com/khulnasoft-lab/vulnmap-ls/infrastructure/iac"
	"github.com/khulnasoft-lab/vulnmap-ls/infrastructure/learn"
	"github.com/khulnasoft-lab/vulnmap-ls/infrastructure/learn/mock_learn"
	"github.com/khulnasoft-lab/vulnmap-ls/infrastructure/oss"
	"github.com/khulnasoft-lab/vulnmap-ls/infrastructure/vulnmap_api"
	domainNotify "github.com/khulnasoft-lab/vulnmap-ls/internal/notification"
)

// TODO this is becoming a hot mess we need to unify integ. test strategies
func TestInit(t *testing.T) {
	initMutex.Lock()
	defer initMutex.Unlock()
	t.Helper()
	c := config.CurrentConfig()
	// we don't want to open browsers when testing
	vulnmap.DefaultOpenBrowserFunc = func(url string) {}
	notifier = domainNotify.NewNotifier()
	analytics = ux.NewTestAnalytics()
	instrumentor = performance.NewInstrumentor()
	errorReporter = er.NewTestErrorReporter()
	installer = install.NewFakeInstaller()
	authProvider := vulnmap.NewFakeCliAuthenticationProvider()
	vulnmapApiClient = &vulnmap_api.FakeApiClient{CodeEnabled: true}
	authenticationService = vulnmap.NewAuthenticationService(authProvider, analytics, errorReporter, notifier)
	vulnmapCli := cli.NewExecutor(authenticationService, errorReporter, analytics, notifier)
	cliInitializer = cli.NewInitializer(errorReporter, installer, notifier, vulnmapCli)
	authInitializer := cliauth.NewInitializer(authenticationService, errorReporter, analytics, notifier)
	scanInitializer = initialize.NewDelegatingInitializer(
		cliInitializer,
		authInitializer,
	)
	fakeClient := &code.FakeVulnmapCodeClient{}
	vulnmapCodeClient = fakeClient
	vulnmapCodeBundleUploader = code.NewBundler(vulnmapCodeClient, instrumentor)
	scanNotifier, _ = appNotification.NewScanNotifier(notifier)
	// mock Learn Service
	learnMock := mock_learn.NewMockService(gomock.NewController(t))
	learnMock.
		EXPECT().
		GetLesson(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&learn.Lesson{}, nil).AnyTimes()
	learnService = learnMock
	vulnmapCodeScanner = code.New(vulnmapCodeBundleUploader, vulnmapApiClient, errorReporter, analytics, learnService, notifier)
	openSourceScanner = oss.NewCLIScanner(instrumentor, errorReporter, analytics, vulnmapCli, learnService, notifier, c)
	infrastructureAsCodeScanner = iac.New(instrumentor, errorReporter, analytics, vulnmapCli)
	scanner = vulnmap.NewDelegatingScanner(
		scanInitializer,
		instrumentor,
		analytics,
		scanNotifier,
		vulnmapApiClient,
		authenticationService,
		notifier,
		vulnmapCodeScanner,
		infrastructureAsCodeScanner,
		openSourceScanner,
	)
	hoverService = hover.NewDefaultService(analytics)
	command.SetService(&vulnmap.CommandServiceMock{})
	// don't use getters or it'll deadlock
	w := workspace.New(instrumentor, scanner, hoverService, scanNotifier, notifier)
	workspace.Set(w)
	fileWatcher = watcher.NewFileWatcher()
	codeActionService = codeaction.NewService(c, w, fileWatcher, notifier, vulnmapCodeClient)
	t.Cleanup(
		func() {
			fakeClient.Clear()
		},
	)
}
