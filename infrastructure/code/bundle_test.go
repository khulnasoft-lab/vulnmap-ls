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
	"testing"

	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/khulnasoft-lab/vulnmap-ls/domain/observability/performance"
	"github.com/khulnasoft-lab/vulnmap-ls/domain/vulnmap"
	"github.com/khulnasoft-lab/vulnmap-ls/internal/data_structure"
	"github.com/khulnasoft-lab/vulnmap-ls/internal/notification"
	"github.com/khulnasoft-lab/vulnmap-ls/internal/util"
)

var bundleWithFiles = &UploadBatch{
	hash:      "bundleWithFilesHash",
	documents: map[string]BundleFile{"file": {}},
}
var bundleWithMultipleFiles = &UploadBatch{
	hash: "bundleWithMultipleFilesHash",
	documents: map[string]BundleFile{
		"file":    {},
		"another": {},
	},
}

func Test_getShardKey(t *testing.T) {
	b := Bundle{BundleHash: ""}
	const testToken = "TEST"
	t.Run("should return root path hash", func(t *testing.T) {
		// Case 1: rootPath exists
		sampleRootPath := "C:\\GIT\\root"
		// deepcode ignore HardcodedPassword/test: false positive
		token := testToken
		assert.Equal(t, util.Hash([]byte(sampleRootPath)), b.getShardKey(sampleRootPath, token))
	})

	t.Run("should return token hash", func(t *testing.T) {
		// Case 2: rootPath empty, token exists
		sampleRootPath := ""
		// deepcode ignore HardcodedPassword/test: false positive
		token := testToken
		assert.Equal(t, util.Hash([]byte(token)), b.getShardKey(sampleRootPath, token))
	})

	t.Run("should return empty shard key", func(t *testing.T) {
		// Case 3: No token, no rootPath set
		sampleRootPath := ""
		// deepcode ignore HardcodedPassword/test: false positive
		token := ""
		assert.Equal(t, "", b.getShardKey(sampleRootPath, token))
	})
}

func Test_BundleGroup_AddBundle(t *testing.T) {
	t.Run("when no documents - creates nothing", func(t *testing.T) {
		fakeVulnmapCode := FakeVulnmapCodeClient{}
		bundle := Bundle{
			VulnmapCode: &fakeVulnmapCode,
		}

		emptyBundle := &UploadBatch{}
		_ = bundle.Upload(context.Background(), emptyBundle)

		assert.False(t, fakeVulnmapCode.HasCreatedNewBundle)
		assert.False(t, fakeVulnmapCode.HasExtendedBundle)
	})

	t.Run("when no bundles - creates new bundle and sets hash", func(t *testing.T) {
		t.Skip("needs to be moved")
		fakeVulnmapCode := FakeVulnmapCodeClient{}
		bundle := Bundle{
			VulnmapCode: &fakeVulnmapCode,
		}

		_ = bundle.Upload(context.Background(), bundleWithFiles)

		assert.False(t, fakeVulnmapCode.HasExtendedBundle)
	})

	t.Run("when existing bundles - extends bundle and updates hash", func(t *testing.T) {
		fakeVulnmapCode := FakeVulnmapCodeClient{}
		bundle := Bundle{
			VulnmapCode: &fakeVulnmapCode,
		}

		_ = bundle.Upload(context.Background(), bundleWithFiles)
		oldHash := bundle.BundleHash
		_ = bundle.Upload(context.Background(), bundleWithMultipleFiles)
		newHash := bundle.BundleHash

		assert.True(t, fakeVulnmapCode.HasExtendedBundle)
		assert.Equal(t, 2, fakeVulnmapCode.TotalBundleCount)
		assert.Equal(t, 2, fakeVulnmapCode.ExtendedBundleCount)
		assert.NotEqual(t, oldHash, newHash)
	})
}

func Test_AutofixMessages(t *testing.T) {
	fakeVulnmapCode := FakeVulnmapCodeClient{}
	mockNotifier := notification.NewMockNotifier()
	bundle := Bundle{
		VulnmapCode:     &fakeVulnmapCode,
		notifier:     mockNotifier,
		instrumentor: performance.NewInstrumentor(),
	}

	t.Run("Shows attempt message when fix requested", func(t *testing.T) {
		fn := bundle.autofixFunc(context.Background(), FakeIssue)
		fn()

		assert.Contains(t, mockNotifier.SentMessages(), sglsp.ShowMessageParams{
			Type:    sglsp.Info,
			Message: "Attempting to fix VULNMAP-123 (Vulnmap)",
		})
	})

	t.Run("Shows success message when fix provided", func(t *testing.T) {
		fn := bundle.autofixFunc(context.Background(), FakeIssue)
		fn()

		successMsgRequest := mockNotifier.SentMessages()[1].(vulnmap.ShowMessageRequest)
		assert.Equal(t, vulnmap.Info, successMsgRequest.Type)
		assert.Equal(t, "Congratulations! 🎉 You’ve just fixed this VULNMAP-123 issue. Was this fix helpful?", successMsgRequest.Message)

		// Compare button action commands
		actionCommandMap := data_structure.NewOrderedMap[vulnmap.MessageAction, vulnmap.CommandData]()
		commandData1 := vulnmap.CommandData{
			Title:     vulnmap.CodeSubmitFixFeedback,
			CommandId: vulnmap.CodeSubmitFixFeedback,
			Arguments: []any{"123e4567-e89b-12d3-a456-426614174000/1", true},
		}
		commandData2 := vulnmap.CommandData{
			Title:     vulnmap.CodeSubmitFixFeedback,
			CommandId: vulnmap.CodeSubmitFixFeedback,
			Arguments: []any{"123e4567-e89b-12d3-a456-426614174000/1", false},
		}
		positiveFeedback := vulnmap.MessageAction("👍")
		negativeFeedback := vulnmap.MessageAction("👎")
		actionCommandMap.Add(positiveFeedback, commandData1)
		actionCommandMap.Add(negativeFeedback, commandData2)

		assert.Equal(t, actionCommandMap.Keys(), successMsgRequest.Actions.Keys())

		buttonAction1, _ := successMsgRequest.Actions.Get(positiveFeedback)
		buttonAction2, _ := successMsgRequest.Actions.Get(negativeFeedback)
		assert.Equal(t, commandData1, buttonAction1)
		assert.Equal(t, commandData2, buttonAction2)
	})

	t.Run("Shows error message when no fix available", func(t *testing.T) {
		fakeVulnmapCode.NoFixSuggestions = true

		fn := bundle.autofixFunc(context.Background(), FakeIssue)
		fn()

		assert.Contains(t, mockNotifier.SentMessages(), sglsp.ShowMessageParams{
			Type:    sglsp.MTError,
			Message: "Oh snap! 😔 The fix did not remediate the issue and was not applied.",
		})
	})
}
