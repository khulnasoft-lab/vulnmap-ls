/*
 * © 2022-2023 Khulnasoft Limited
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

package oss

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/khulnasoft-lab/vulnmap-ls/application/config"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/vulnmap"
)

func TestNpmRangeFinder_Find(t *testing.T) {
	config.CurrentConfig().SetFormat(config.FormatHtml)

	var issue = ossIssue{
		Id:             "testIssue",
		Name:           "VULNMAP-TEST-ISSUE-1",
		Title:          "THOU SHALL NOT PASS",
		Severity:       "1",
		LineNumber:     0,
		Description:    "Getting into Moria is an issue!",
		References:     nil,
		Version:        "",
		PackageManager: "npm",
		From:           []string{"goof@1.0.1", "lodash@4.17.4"},
	}

	var testPath, _ = filepath.Abs("testdata/package.json")
	var testContent, _ = os.ReadFile(testPath)
	npmRangeFinder := NpmRangeFinder{
		uri:         testPath,
		fileContent: testContent,
		myRange:     vulnmap.Range{},
	}
	expectedRange := vulnmap.Range{
		Start: vulnmap.Position{
			Line:      17,
			Character: 4,
		},
		End: vulnmap.Position{
			Line:      17,
			Character: 22,
		},
	}

	actualRange := npmRangeFinder.find(issue)
	assert.Equal(t, expectedRange, actualRange)
}

func TestNpmRangeFinder_Find_Scoped_Packages(t *testing.T) {
	config.CurrentConfig().SetFormat(config.FormatHtml)

	var issue = ossIssue{
		Id:             "testIssue",
		Name:           "VULNMAP-TEST-ISSUE-1",
		Title:          "THOU SHALL NOT PASS",
		Severity:       "1",
		LineNumber:     0,
		Description:    "Getting into Moria is an issue!",
		References:     nil,
		Version:        "",
		PackageManager: "npm",
		From:           []string{"goof@1.0.1", "@angular/cli@1.0.0"},
	}

	var testPath, _ = filepath.Abs("testdata/package.json")
	var testContent, _ = os.ReadFile(testPath)
	npmRangeFinder := NpmRangeFinder{
		uri:         testPath,
		fileContent: testContent,
		myRange:     vulnmap.Range{},
	}
	expectedRange := vulnmap.Range{
		Start: vulnmap.Position{
			Line:      18,
			Character: 4,
		},
		End: vulnmap.Position{
			Line:      18,
			Character: 27,
		},
	}

	actualRange := npmRangeFinder.find(issue)
	assert.Equal(t, expectedRange, actualRange)
}
