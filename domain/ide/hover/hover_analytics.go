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

package hover

import (
	"github.com/khulnasoft-lab/vulnmap-ls/domain/observability/ux"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/vulnmap"
)

func NewIssueHoverIsDisplayedProperties(issue vulnmap.Issue) ux.IssueHoverIsDisplayedProperties {
	return ux.IssueHoverIsDisplayedProperties{
		IssueId:   issue.ID,
		IssueType: types[issue.IssueType],
		Severity:  severities[issue.Severity],
	}
}

var (
	types = map[vulnmap.Type]ux.IssueType{
		vulnmap.PackageHealth:             ux.AdvisorIssue,
		vulnmap.CodeQualityIssue:          ux.CodeQualityIssue,
		vulnmap.CodeSecurityVulnerability: ux.CodeSecurityVulnerability,
		vulnmap.LicenceIssue:              ux.LicenceIssue,
		vulnmap.DependencyVulnerability:   ux.OpenSourceVulnerability,
		vulnmap.InfrastructureIssue:       ux.InfrastructureAsCodeIssue,
		vulnmap.ContainerVulnerability:    ux.ContainerVulnerability,
	}
	severities = map[vulnmap.Severity]ux.Severity{
		vulnmap.Critical: ux.Critical,
		vulnmap.High:     ux.High,
		vulnmap.Medium:   ux.Medium,
		vulnmap.Low:      ux.Low,
	}
)
