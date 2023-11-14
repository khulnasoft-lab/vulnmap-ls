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

package command

import (
	"context"

	"github.com/pkg/errors"

	"github.com/khulnasoft-lab/vulnmap-ls/domain/vulnmap"
	"github.com/khulnasoft-lab/vulnmap-ls/infrastructure/learn"
	"github.com/khulnasoft-lab/vulnmap-ls/internal/lsp"
)

type openLearnLesson struct {
	command               vulnmap.CommandData
	srv                   lsp.Server
	learnService          learn.Service
	openBrowserHandleFunc func(url string)
}

func (cmd *openLearnLesson) Command() vulnmap.CommandData {
	return cmd.command
}

func (cmd *openLearnLesson) Execute(_ context.Context) (any, error) {
	args := cmd.command.Arguments
	if len(args) < 5 {
		return nil, errors.New("command is missing arguments. expected: rule, ecosystem, cwes, cves, issueType")
	}

	lesson, err := learnLesson(args, cmd.learnService)

	if cmd.openBrowserHandleFunc != nil {
		cmd.openBrowserHandleFunc(lesson.Url)
	} else {
		vulnmap.DefaultOpenBrowserFunc(lesson.Url)
	}
	return lesson, err
}
