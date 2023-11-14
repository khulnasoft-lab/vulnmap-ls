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

package di

import (
	"path/filepath"
	"runtime"
	"sync"

	"github.com/khulnasoft-lab/vulnmap-ls/infrastructure/cli/cli_constants"

	"github.com/adrg/xdg"

	"github.com/khulnasoft-lab/vulnmap-ls/application/codeaction"
	"github.com/khulnasoft-lab/vulnmap-ls/application/config"
	appNotification "github.com/khulnasoft-lab/vulnmap-ls/application/server/notification"
	"github.com/khulnasoft-lab/vulnmap-ls/application/watcher"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/ide/command"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/ide/hover"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/ide/initialize"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/ide/notification"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/ide/workspace"
	er "github.com/khulnasoft-lab/vulnmap-ls/domain/observability/error_reporting"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/observability/performance"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/observability/ux"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/vulnmap"
	"github.com/khulnasoft-lab/vulnmap-ls/infrastructure/amplitude"
	"github.com/khulnasoft-lab/vulnmap-ls/infrastructure/cli"
	cliauth "github.com/khulnasoft-lab/vulnmap-ls/infrastructure/cli/auth"
	"github.com/khulnasoft-lab/vulnmap-ls/infrastructure/cli/install"
	"github.com/khulnasoft-lab/vulnmap-ls/infrastructure/code"
	"github.com/khulnasoft-lab/vulnmap-ls/infrastructure/iac"
	"github.com/khulnasoft-lab/vulnmap-ls/infrastructure/learn"
	"github.com/khulnasoft-lab/vulnmap-ls/infrastructure/oss"
	"github.com/khulnasoft-lab/vulnmap-ls/infrastructure/sentry"
	"github.com/khulnasoft-lab/vulnmap-ls/infrastructure/vulnmap_api"
	domainNotify "github.com/khulnasoft-lab/vulnmap-ls/internal/notification"
)

var vulnmapApiClient vulnmap_api.VulnmapApiClient
var vulnmapCodeClient code.VulnmapCodeClient
var vulnmapCodeBundleUploader *code.BundleUploader
var vulnmapCodeScanner *code.Scanner
var infrastructureAsCodeScanner *iac.Scanner
var openSourceScanner vulnmap.ProductScanner
var scanInitializer initialize.Initializer
var authenticationService vulnmap.AuthenticationService
var learnService learn.Service
var instrumentor performance.Instrumentor
var errorReporter er.ErrorReporter
var installer install.Installer
var analytics ux.Analytics
var hoverService hover.Service
var scanner vulnmap.Scanner
var cliInitializer *cli.Initializer
var scanNotifier vulnmap.ScanNotifier
var codeActionService *codeaction.CodeActionsService
var fileWatcher *watcher.FileWatcher
var initMutex = &sync.Mutex{}
var notifier notification.Notifier

func Init() {
	initMutex.Lock()
	defer initMutex.Unlock()
	initInfrastructure()
	initDomain()
	initApplication()
}

func initDomain() {
	hoverService = hover.NewDefaultService(analytics)
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
}

func initInfrastructure() {
	c := config.CurrentConfig()
	//goland:noinspection GoBoolExpressions
	if runtime.GOOS == "windows" {
		// on windows add the locations in the background, as it can take a while and shouldn't block the server
		go c.AddBinaryLocationsToPath([]string{
			"C:\\Program Files",
			"C:\\Program Files (x86)",
		})
	} else {
		c.AddBinaryLocationsToPath(
			[]string{
				filepath.Join(xdg.Home, ".sdkman"),
				"/usr/lib",
				"/usr/java",
				"/opt",
				"/Library",
			})
	}

	// init NetworkAccess
	networkAccess := c.Engine().GetNetworkAccess()

	notifier = domainNotify.NewNotifier()
	errorReporter = sentry.NewSentryErrorReporter(notifier)
	installer = install.NewInstaller(errorReporter, networkAccess.GetUnauthorizedHttpClient)
	learnService = learn.New(c, networkAccess.GetUnauthorizedHttpClient, errorReporter)
	instrumentor = performance.NewInstrumentor()
	vulnmapApiClient = vulnmap_api.NewVulnmapApiClient(networkAccess.GetHttpClient)
	analytics = amplitude.NewAmplitudeClient(vulnmap.AuthenticationCheck, errorReporter)
	authProvider := cliauth.NewCliAuthenticationProvider(errorReporter)
	authenticationService = vulnmap.NewAuthenticationService(authProvider, analytics, errorReporter, notifier)
	vulnmapCli := cli.NewExecutor(authenticationService, errorReporter, analytics, notifier)

	if c.Engine().GetConfiguration().GetString(cli_constants.EXECUTION_MODE_KEY) == cli_constants.EXECUTION_MODE_VALUE_EXTENSION {
		vulnmapCli = cli.NewExtensionExecutor()
	}

	vulnmapCodeClient = code.NewHTTPRepository(instrumentor, errorReporter, networkAccess.GetHttpClient)
	vulnmapCodeBundleUploader = code.NewBundler(vulnmapCodeClient, instrumentor)
	infrastructureAsCodeScanner = iac.New(instrumentor, errorReporter, analytics, vulnmapCli)
	openSourceScanner = oss.NewCLIScanner(instrumentor, errorReporter, analytics, vulnmapCli, learnService, notifier, c)
	scanNotifier, _ = appNotification.NewScanNotifier(notifier)
	vulnmapCodeScanner = code.New(vulnmapCodeBundleUploader, vulnmapApiClient, errorReporter, analytics, learnService, notifier)
	cliInitializer = cli.NewInitializer(errorReporter, installer, notifier, vulnmapCli)
	authInitializer := cliauth.NewInitializer(authenticationService, errorReporter, analytics, notifier)
	scanInitializer = initialize.NewDelegatingInitializer(
		cliInitializer,
		authInitializer,
	)
}

func initApplication() {
	w := workspace.New(instrumentor, scanner, hoverService, scanNotifier, notifier) // don't use getters or it'll deadlock
	workspace.Set(w)
	fileWatcher = watcher.NewFileWatcher()
	codeActionService = codeaction.NewService(config.CurrentConfig(), w, fileWatcher, notifier, vulnmapCodeClient)
	command.SetService(command.NewService(authenticationService, notifier, learnService, w, vulnmapCodeClient))
}

/*
TODO Accessors: This should go away, since all dependencies should be satisfied at startup-time, if needed for testing
they can be returned by the test helper for unit/integration tests
*/

func Notifier() notification.Notifier {
	initMutex.Lock()
	defer initMutex.Unlock()
	return notifier
}

func ErrorReporter() er.ErrorReporter {
	initMutex.Lock()
	defer initMutex.Unlock()
	return errorReporter
}

func AuthenticationService() vulnmap.AuthenticationService {
	initMutex.Lock()
	defer initMutex.Unlock()
	return authenticationService
}

func HoverService() hover.Service {
	initMutex.Lock()
	defer initMutex.Unlock()
	return hoverService
}

func ScanNotifier() vulnmap.ScanNotifier {
	initMutex.Lock()
	defer initMutex.Unlock()
	return scanNotifier
}

func Scanner() vulnmap.Scanner {
	initMutex.Lock()
	defer initMutex.Unlock()
	return scanner
}

func Initializer() initialize.Initializer {
	initMutex.Lock()
	defer initMutex.Unlock()
	return scanInitializer
}

func Analytics() ux.Analytics {
	initMutex.Lock()
	defer initMutex.Unlock()
	return analytics
}

func Installer() install.Installer {
	initMutex.Lock()
	defer initMutex.Unlock()
	return installer
}

func CodeActionService() *codeaction.CodeActionsService {
	initMutex.Lock()
	defer initMutex.Unlock()
	return codeActionService
}

func FileWatcher() *watcher.FileWatcher {
	initMutex.Lock()
	defer initMutex.Unlock()
	return fileWatcher
}

func LearnService() learn.Service {
	initMutex.Lock()
	defer initMutex.Unlock()
	return learnService
}
