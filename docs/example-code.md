This is a scanner implementation example. See `infrastructure/vulnmap/scanner/emoji.go` for the implementation.

```go
// code from `infrastructure/vulnmap/scanner/emoji.go`
package emoji

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/khulnasoft-lab/vulnmap-ls/domain/observability/error_reporting"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/vulnmap"
)

const (
	catsEvilProof = "https://www.scmp.com/yp/discover/lifestyle/features/article/3071676/13-reasons-why-cats-are-just-plain-evil"
)

type EmojiScanner struct {
	errorReporter    error_reporting.ErrorReporter
	catsEvilProofUrl *url.URL
}

func New(errorReporter error_reporting.ErrorReporter) *EmojiScanner {
	catsEvilProofUrl, _ := url.Parse(catsEvilProof)

	return &EmojiScanner{
		errorReporter,
		catsEvilProofUrl,
	}
}

func (sc *EmojiScanner) Scan(ctx context.Context, path string, folderPath string) []vulnmap.Issue {
	fileInfo, err := os.Stat(path)
	if err != nil {
		// error handling
		sc.errorReporter.CaptureError(err)
		log.Err(err).Str("method", "emoji.Scan").Msg("Error while getting file info.")
	}

	if fileInfo.IsDir() {
		// our scanner don't need to scan folders, instead we operate on a file basis.
		return []vulnmap.Issue{}
	}

	bytes, err := os.ReadFile(path)
	if err != nil {
		sc.errorReporter.CaptureError(err)
		log.Err(err).Str("method", "emoji.Scan").Msg("Error while reading a file")
	}

	emojiRegexp := regexp.MustCompile(`\x{1F408}`) // 🐈 cat emoji regexp

	issues := make([]vulnmap.Issue, 0)

	lines := strings.Split(strings.ReplaceAll(string(bytes), "\r", ""), "\n") // split lines
	for i, line := range lines {
		locs := emojiRegexp.FindAllStringIndex(line, len(line))
		if locs == nil {
			continue // no cat emoji found
		}

		for _, loc := range locs {
			r := vulnmap.Range{
				Start: vulnmap.Position{Line: i, Character: loc[0]},
				End:   vulnmap.Position{Line: i, Character: loc[0] + 1},
			}

			textEdit := vulnmap.TextEdit{
				Range:   r,
				NewText: "woof!",
			}
			replaceCodeAction := vulnmap.CodeAction{
				Title: "Replace with 🐕",
				Edit: vulnmap.WorkspaceEdit{
					Changes: map[string][]vulnmap.TextEdit{
						path: {textEdit},
					},
				},
			}
			learnCodeAction := vulnmap.CodeAction{
				Title: "Learn why cats are evil",
				Command: vulnmap.Command{
					Title:     "Learn why",
					Command:   vulnmap.OpenBrowserCommand,
					Arguments: []interface{}{sc.catsEvilProofUrl.String()},
				},
			}

			issue := vulnmap.NewIssue(
				"So now you know",
				vulnmap.Low,
				vulnmap.EmojiIssue,
				r,
				"Cats are not allowed in this project",
				sc.GetFormattedMessage(),
				path,
				sc.Product(),
				[]vulnmap.Reference{},
				sc.catsEvilProofUrl,
				[]vulnmap.CodeAction{replaceCodeAction, learnCodeAction},
				[]vulnmap.Command{},
			)

			issues = append(issues, issue)
		}
	}

	return issues
}

func (sc *EmojiScanner) IsEnabled() bool {
	return true
}

func (sc *EmojiScanner) Product() vulnmap.Product {
	return vulnmap.ProductEmoji
}

func (sc *EmojiScanner) GetFormattedMessage() string {
	return fmt.Sprintf("## Cats are evil \n You can find proof by navigating to [this link](%s)", catsEvilProof)
}
```
