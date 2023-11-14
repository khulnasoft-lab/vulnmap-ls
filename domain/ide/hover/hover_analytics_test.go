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
	"reflect"
	"testing"

	"github.com/khulnasoft-lab/vulnmap-ls/domain/observability/ux"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/vulnmap"
)

func TestNewIssueHoverIsDisplayedProperties(t *testing.T) {
	tests := []struct {
		name   string
		input  vulnmap.Issue
		output ux.IssueHoverIsDisplayedProperties
	}{
		{
			name: "critical issues",
			input: vulnmap.Issue{
				ID:        "id",
				Severity:  vulnmap.Critical,
				IssueType: vulnmap.PackageHealth,
			},
			output: ux.IssueHoverIsDisplayedProperties{
				IssueId:   "id",
				Severity:  ux.Critical,
				IssueType: ux.AdvisorIssue,
			},
		},
		{
			name: "high severity issues",
			input: vulnmap.Issue{
				ID:        "id",
				Severity:  vulnmap.High,
				IssueType: vulnmap.PackageHealth,
			},
			output: ux.IssueHoverIsDisplayedProperties{
				IssueId:   "id",
				Severity:  ux.High,
				IssueType: ux.AdvisorIssue,
			},
		},
		{
			name: "medium severity issues",
			input: vulnmap.Issue{
				ID:        "id",
				Severity:  vulnmap.Medium,
				IssueType: vulnmap.PackageHealth,
			},
			output: ux.IssueHoverIsDisplayedProperties{
				IssueId:   "id",
				Severity:  ux.Medium,
				IssueType: ux.AdvisorIssue,
			},
		},
		{
			name: "low severity issues",
			input: vulnmap.Issue{
				ID:        "id",
				Severity:  vulnmap.Low,
				IssueType: vulnmap.PackageHealth,
			},
			output: ux.IssueHoverIsDisplayedProperties{
				IssueId:   "id",
				Severity:  ux.Low,
				IssueType: ux.AdvisorIssue,
			},
		},
		{
			name: "oss issues",
			input: vulnmap.Issue{
				ID:        "id",
				Severity:  vulnmap.Critical,
				IssueType: vulnmap.DependencyVulnerability,
			},
			output: ux.IssueHoverIsDisplayedProperties{
				IssueId:   "id",
				Severity:  ux.Critical,
				IssueType: ux.OpenSourceVulnerability,
			},
		},
		{
			name: "iac issues",
			input: vulnmap.Issue{
				ID:        "id",
				Severity:  vulnmap.Critical,
				IssueType: vulnmap.InfrastructureIssue,
			},
			output: ux.IssueHoverIsDisplayedProperties{
				IssueId:   "id",
				Severity:  ux.Critical,
				IssueType: ux.InfrastructureAsCodeIssue,
			},
		},
		{
			name: "code security issues",
			input: vulnmap.Issue{
				ID:        "id",
				Severity:  vulnmap.Critical,
				IssueType: vulnmap.CodeSecurityVulnerability,
			},
			output: ux.IssueHoverIsDisplayedProperties{
				IssueId:   "id",
				Severity:  ux.Critical,
				IssueType: ux.CodeSecurityVulnerability,
			},
		},
		{
			name: "code quality issues",
			input: vulnmap.Issue{
				ID:        "id",
				Severity:  vulnmap.Critical,
				IssueType: vulnmap.CodeQualityIssue,
			},
			output: ux.IssueHoverIsDisplayedProperties{
				IssueId:   "id",
				Severity:  ux.Critical,
				IssueType: ux.CodeQualityIssue,
			},
		},
		{
			name: "code quality issues",
			input: vulnmap.Issue{
				ID:        "id",
				Severity:  vulnmap.Critical,
				IssueType: vulnmap.LicenceIssue,
			},
			output: ux.IssueHoverIsDisplayedProperties{
				IssueId:   "id",
				Severity:  ux.Critical,
				IssueType: ux.LicenceIssue,
			},
		},
		{
			name: "code quality issues",
			input: vulnmap.Issue{
				ID:        "id",
				Severity:  vulnmap.Critical,
				IssueType: vulnmap.ContainerVulnerability,
			},
			output: ux.IssueHoverIsDisplayedProperties{
				IssueId:   "id",
				Severity:  ux.Critical,
				IssueType: ux.ContainerVulnerability,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewIssueHoverIsDisplayedProperties(tt.input); !reflect.DeepEqual(got, tt.output) {
				t.Errorf("NewIssueHoverIsDisplayedProperties() = %v, want %v", got, tt.output)
			}
		})
	}
}
