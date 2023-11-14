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

package codelens

import (
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/khulnasoft-lab/vulnmap-ls/domain/ide/converter"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/ide/workspace"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/vulnmap"
)

func GetFor(filePath string) (lenses []sglsp.CodeLens) {
	f := workspace.Get().GetFolderContaining(filePath)
	if f == nil {
		return lenses
	}

	issues := f.DocumentDiagnosticsFromCache(filePath)
	for _, issue := range issues {
		for _, command := range issue.CodelensCommands {
			lenses = append(lenses, getCodeLensFromCommand(issue, command))
		}
	}
	return lenses
}

func getCodeLensFromCommand(issue vulnmap.Issue, command vulnmap.CommandData) sglsp.CodeLens {
	return sglsp.CodeLens{
		Range: converter.ToRange(issue.Range),
		Command: sglsp.Command{
			Title:     command.Title,
			Command:   command.CommandId,
			Arguments: command.Arguments,
		},
	}
}
