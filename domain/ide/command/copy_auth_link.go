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

	"github.com/atotto/clipboard"
	"github.com/rs/zerolog/log"

	noti "github.com/khulnasoft-lab/vulnmap-ls/domain/ide/notification"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/vulnmap"
)

type copyAuthLinkCommand struct {
	command     vulnmap.CommandData
	authService vulnmap.AuthenticationService
	notifier    noti.Notifier
}

func (cmd *copyAuthLinkCommand) Command() vulnmap.CommandData {
	return cmd.command
}

func (cmd *copyAuthLinkCommand) Execute(ctx context.Context) (any, error) {
	url := cmd.authService.Provider().AuthURL(ctx)
	log.Debug().Str("method", "copyAuthLinkCommand.Execute").
		Str("url", url).
		Msgf("copying auth link to clipboard")
	err := clipboard.WriteAll(url)

	if err != nil {
		log.Err(err).Msg("Error on vulnmap.copyAuthLink command")
		cmd.notifier.SendError(err)
	}
	return url, err
}
