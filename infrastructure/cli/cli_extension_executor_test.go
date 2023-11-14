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

package cli

import (
	"context"
	"testing"

	"github.com/khulnasoft-lab/vulnmap-ls/internal/testutil"

	"github.com/khulnasoft-lab/go-application-framework/pkg/app"
	"github.com/khulnasoft-lab/go-application-framework/pkg/configuration"
	"github.com/khulnasoft-lab/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"

	"github.com/khulnasoft-lab/vulnmap-ls/application/config"
)

func Test_ExecuteLegacyCLI_SUCCESS(t *testing.T) {
	testutil.UnitTest(t)

	// Prepare
	cmd := []string{"vulnmap", "test"}
	expectedVulnmapCommand := cmd[1:]
	actualVulnmapCommand := []string{}

	expectedWorkingDir := "my work dir"
	actualWorkingDir := ""

	expectedPayload := []byte("hello")

	workflowId := workflow.NewWorkflowIdentifier("legacycli")
	engine := app.CreateAppEngine()
	_, err := engine.Register(workflowId, workflow.ConfigurationOptionsFromFlagset(&pflag.FlagSet{}), func(invocation workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
		config := invocation.GetConfiguration()
		actualVulnmapCommand = config.GetStringSlice(configuration.RAW_CMD_ARGS)
		actualWorkingDir = config.GetString(configuration.WORKING_DIRECTORY)
		data := workflow.NewData(workflow.NewTypeIdentifier(workflowId, "testdata"), "txt", expectedPayload)
		return []workflow.Data{data}, nil
	})
	assert.Nil(t, err)

	err = engine.Init()
	assert.Nil(t, err)

	config.CurrentConfig().SetEngine(engine)

	// Run
	executorUnderTest := NewExtensionExecutor()
	actualData, err := executorUnderTest.Execute(context.Background(), cmd, expectedWorkingDir)
	assert.Nil(t, err)

	// Compare
	assert.Equal(t, expectedPayload, actualData)
	assert.Equal(t, expectedVulnmapCommand, actualVulnmapCommand)
	assert.Equal(t, expectedWorkingDir, actualWorkingDir)

}

func Test_ExecuteLegacyCLI_FAILED(t *testing.T) {
	testutil.UnitTest(t)

	// Prepare
	engine := app.CreateAppEngine()
	config.CurrentConfig().SetEngine(engine)
	cmd := []string{"vulnmap", "test"}
	expectedPayload := []byte{}

	// Run
	executorUnderTest := NewExtensionExecutor()
	actualData, err := executorUnderTest.Execute(context.Background(), cmd, "")

	// Compare
	assert.NotNil(t, err)
	assert.Equal(t, expectedPayload, actualData)

}
