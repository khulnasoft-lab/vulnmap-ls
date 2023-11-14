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

package install

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/khulnasoft-lab/vulnmap-ls/application/config"
	"github.com/khulnasoft-lab/vulnmap-ls/internal/lsp"
	"github.com/khulnasoft-lab/vulnmap-ls/internal/progress"
	"github.com/khulnasoft-lab/vulnmap-ls/internal/testutil"
)

func TestDownloader_Download(t *testing.T) {
	testutil.IntegTest(t)
	r := getTestAsset()
	progressCh := make(chan lsp.ProgressParams, 100000)
	cancelProgressCh := make(chan lsp.ProgressToken, 1)
	d := &Downloader{
		progressTracker: progress.NewTestTracker(progressCh, cancelProgressCh),
		httpClient:      func() *http.Client { return http.DefaultClient },
	}
	exec := (&Discovery{}).ExecutableName(false)
	destination := filepath.Join(t.TempDir(), exec)
	config.CurrentConfig().CliSettings().SetPath(destination)
	lockFileName := d.lockFileName()
	// remove any existing lockfile
	_ = os.RemoveAll(lockFileName)

	err := d.Download(r, false)

	assert.NoError(t, err)
	assert.NotEmpty(t, progressCh)
	assert.True(t, len(progressCh) >= 3) // has at least started, reported & finished progress

	//make sure cleanup works
	_, err = os.Stat(lockFileName)
	if err == nil {
		_ = os.RemoveAll(lockFileName)
	}
	assert.Error(t, err)
}

func Test_DoNotDownloadIfCancelled(t *testing.T) {
	testutil.UnitTest(t)
	progressCh := make(chan lsp.ProgressParams, 100000)
	cancelProgressCh := make(chan lsp.ProgressToken, 1)
	d := &Downloader{
		progressTracker: progress.NewTestTracker(progressCh, cancelProgressCh),
		httpClient:      func() *http.Client { return http.DefaultClient },
	}

	r := getTestAsset()

	// simulate cancellation when some progress received
	go func() {
		prog := <-progressCh
		cancelProgressCh <- prog.Token
	}()

	err := d.Download(r, false)

	assert.Error(t, err)

	// make sure cancellation cleanup works
	_, err = os.Stat(config.CurrentConfig().CLIDownloadLockFileName())
	if err == nil {
		assert.Error(t, err)
	}
}

func getTestAsset() *Release {
	r := &Release{
		Assets: &ReleaseAssets{
			MacOS: &ReleaseAsset{
				URL:          "https://static.vulnmap.khulnasoft.com/cli/v1.1141.0/vulnmap-macos",
				ChecksumInfo: "f1ab84a2ad80d99c6293dda5bc7a80f0511222b29150960ff74c556966000c48  vulnmap-macos",
			},
			Linux: &ReleaseAsset{
				URL:          "https://static.vulnmap.khulnasoft.com/cli/v1.1141.0/vulnmap-linux",
				ChecksumInfo: "d516eb4623acc86225efc4d6b29e1627ce541909cbbe89175f8b0e8285d3b359  vulnmap-linux",
			},
			LinuxARM64: &ReleaseAsset{
				URL:          "https://static.vulnmap.khulnasoft.com/cli/v1.1141.0/vulnmap-linux-arm64",
				ChecksumInfo: "6d146cd8891c79234b6be3970ef6e6168fa250dd9f1257dbba6543d25f1ae797  vulnmap-linux-arm64",
			},
			Windows: &ReleaseAsset{
				URL:          "https://static.vulnmap.khulnasoft.com/cli/v1.1141.0/vulnmap-win.exe",
				ChecksumInfo: "68f7dc7565f7b4efd9516b5436c8cbf9217138194141636c39264ff6e4407bf9  vulnmap-win.exe",
			},
		},
	}
	return r
}
