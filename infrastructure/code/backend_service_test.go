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
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/google/uuid"

	"github.com/khulnasoft-lab/vulnmap-ls/application/config"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/observability/error_reporting"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/observability/performance"
	"github.com/khulnasoft-lab/vulnmap-ls/internal/testutil"
	"github.com/khulnasoft-lab/vulnmap-ls/internal/util"
)

const (
	path1   = "/AnnotatorTest.java"
	path2   = "/AnnotatorTest2.java"
	content = `public class AnnotatorTest {
  public static void delay(long millis) {
    try {
      Thread.sleep(millis);
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
  }
}`
	content2 = `public class AnnotatorTest2 {
  public static void delay(long millis) {
    try {
      Thread.sleep(millis);
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
  }
}`
)

func clientFunc() *http.Client {
	return config.CurrentConfig().Engine().GetNetworkAccess().GetHttpClient()
}

func TestVulnmapCodeBackendService_CreateBundle(t *testing.T) {
	testutil.SmokeTest(t)

	s := NewHTTPRepository(performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), clientFunc)
	files := map[string]string{}
	randomAddition := fmt.Sprintf("\n public void random() { System.out.println(\"%d\") }", time.Now().UnixMicro())
	files[path1] = util.Hash([]byte(content + randomAddition))
	bundleHash, missingFiles, _ := s.CreateBundle(context.Background(), files)
	assert.NotNil(t, bundleHash)
	assert.NotEqual(t, "", bundleHash)
	assert.Equal(t, 1, len(missingFiles))
}

func TestVulnmapCodeBackendService_ExtendBundle(t *testing.T) {
	testutil.SmokeTest(t)
	s := NewHTTPRepository(performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), clientFunc)
	var removedFiles []string
	files := map[string]string{}
	files[path1] = util.Hash([]byte(content))
	bundleHash, _, _ := s.CreateBundle(context.Background(), files)
	filesExtend := createTestExtendMap()

	bundleHash, missingFiles, _ := s.ExtendBundle(context.Background(), bundleHash, filesExtend, removedFiles)

	assert.Equal(t, 0, len(missingFiles))
	assert.NotEmpty(t, bundleHash)
}

func createTestExtendMap() map[string]BundleFile {
	filesExtend := map[string]BundleFile{}

	filesExtend[path1] = BundleFile{
		Hash:    util.Hash([]byte(content)),
		Content: content,
	}
	filesExtend[path2] = BundleFile{
		Hash:    util.Hash([]byte(content2)),
		Content: content2,
	}
	return filesExtend
}

// dummyTransport is a transport struct that always returns the response code specified in the constructor
type dummyTransport struct {
	responseCode int
	status       string
	calls        int
}

func (d *dummyTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	d.calls++
	return &http.Response{
		StatusCode: d.responseCode,
		Status:     d.status,
	}, nil
}

func TestVulnmapCodeBackendService_doCall_shouldRetry(t *testing.T) {
	testutil.UnitTest(t)
	d := &dummyTransport{responseCode: 502, status: "502 Bad Gateway"}
	dummyClientFunc := func() *http.Client {
		return &http.Client{
			Transport: d,
		}
	}
	s := NewHTTPRepository(performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), dummyClientFunc)
	_, err := s.doCall(context.Background(), "GET", "https://httpstat.us/500", nil)
	assert.Error(t, err)
	assert.Equal(t, 3, d.calls)
}

func TestVulnmapCodeBackendService_RunAnalysisSmoke(t *testing.T) {
	testutil.SmokeTest(t)
	config.CurrentConfig().SetVulnmapCodeEnabled(true)

	s := NewHTTPRepository(performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), clientFunc)
	shardKey := util.Hash([]byte("/"))
	var removedFiles []string
	files := map[string]string{}
	files[path1] = util.Hash([]byte(content))
	bundleHash, _, _ := s.CreateBundle(context.Background(), files)
	filesExtend := createTestExtendMap()
	bundleHash, missingFiles, _ := s.ExtendBundle(context.Background(), bundleHash, filesExtend, removedFiles)
	assert.Len(t, missingFiles, 0, "all files should be uploaded now")

	assert.Eventually(t, func() bool {
		limitToFiles := []string{path1, path2}

		analysisOptions := AnalysisOptions{
			bundleHash:   bundleHash,
			shardKey:     shardKey,
			limitToFiles: limitToFiles,
			severity:     0,
		}
		issues, callStatus, err := s.RunAnalysis(context.Background(), analysisOptions, "")
		if err != nil {
			return false
		}
		if callStatus.message == "COMPLETE" && issues != nil {
			return assert.NotEqual(t, 0, len(issues))
		}
		return false
	}, 120*time.Second, 2*time.Second)
}

// todo analysis test limit files
// todo analysis test severities

func TestGetCodeApiUrl(t *testing.T) {

	t.Run("Vulnmapgov instances code api url generation", func(t *testing.T) {
		t.Setenv("DEEPROXY_API_URL", "")

		var vulnmapgovInstances = []string{
			"vulnmapgov",
			"fedramp-alpha.vulnmapgov",
		}

		for _, instance := range vulnmapgovInstances {
			inputList := []string{
				"https://" + instance + ".io/api/v1",
				"https://" + instance + ".io/api",
				"https://app." + instance + ".io/api",
				"https://app." + instance + ".io/api/v1",
				"https://api." + instance + ".io/api/v1",
				"https://api." + instance + ".io/v1",
				"https://api." + instance + ".io",
				"https://api." + instance + ".io?something=here",
			}

			for _, input := range inputList {
				c := config.CurrentConfig()
				random, _ := uuid.NewRandom()
				orgUUID := random.String()

				c.UpdateApiEndpoints(input)
				c.SetOrganization(orgUUID)

				expected := "https://api." + instance + ".io/hidden/orgs/" + orgUUID + "/code"

				actual, err := getCodeApiUrl(c)
				assert.Nil(t, err)
				assert.Contains(t, actual, expected)
			}
		}
	})

	t.Run("Deeproxy instances code api url generation", func(t *testing.T) {
		t.Setenv("DEEPROXY_API_URL", "")

		var deeproxyInstances = []string{
			"vulnmap",
			"au.vulnmap",
			"dev.vulnmap",
		}

		for _, instance := range deeproxyInstances {
			inputList := []string{
				"https://" + instance + ".io/api/v1",
				"https://" + instance + ".io/api",
				"https://app." + instance + ".io/api",
				"https://app." + instance + ".io/api/v1",
				"https://api." + instance + ".io/api/v1",
				"https://api." + instance + ".io/v1",
				"https://api." + instance + ".io",
				"https://api." + instance + ".io?something=here",
			}

			expected := "https://deeproxy." + instance + ".io"

			for _, input := range inputList {
				c := config.CurrentConfig()
				c.UpdateApiEndpoints(input)

				actual, err := getCodeApiUrl(c)
				t.Log(input, actual)
				assert.Nil(t, err)
				assert.Contains(t, actual, expected)
			}
		}
	})

	t.Run("Default deeprox url for code api", func(t *testing.T) {
		c := config.CurrentConfig()

		url, _ := getCodeApiUrl(c)
		assert.Equal(t, c.VulnmapCodeApi(), url)
	})
}
