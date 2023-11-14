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

package oss

import (
	"fmt"

	"github.com/khulnasoft-lab/vulnmap-ls/application/config"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/vulnmap"
	"github.com/khulnasoft-lab/vulnmap-ls/infrastructure/oss/parser"
)

type htmlRangeFinder struct {
	path        string
	fileContent []byte
	config      *config.Config
}

func (h htmlRangeFinder) find(issue ossIssue) vulnmap.Range {
	dependencyParser := parser.NewParser(h.config, h.path)
	dependencies, err := dependencyParser.Parse(h.path)
	if err != nil {
		return vulnmap.Range{}
	}
	for _, dependency := range dependencies {
		if fmt.Sprintf("%s@%s", dependency.ArtifactID, dependency.Version) == issue.From[0] {
			return dependency.Range
		}
	}
	return vulnmap.Range{}
}

var _ RangeFinder = &htmlRangeFinder{}
