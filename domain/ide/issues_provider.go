package ide

import "github.com/khulnasoft-lab/vulnmap-ls/domain/vulnmap"

// IssueProvider is an interface that allows to retrieve issues for a given path and range.
// This is used instead of any concrete dependency to allow for easier testing and more flexibility in implementation.
type IssueProvider interface {
	IssuesFor(path string, r vulnmap.Range) []vulnmap.Issue
}
