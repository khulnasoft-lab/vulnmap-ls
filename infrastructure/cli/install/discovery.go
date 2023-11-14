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

package install

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/adrg/xdg"

	"github.com/khulnasoft-lab/vulnmap-ls/application/config"
	"github.com/khulnasoft-lab/vulnmap-ls/infrastructure/cli/filename"
)

const userDirName = "vulnmap-ls"

type Discovery struct{}

// LookPath searches for the Vulnmap CLI executable in the directories named by the PATH environment variable.
func (d *Discovery) LookPath() (string, error) {
	path, err := exec.LookPath(filename.ExecutableName)
	if err != nil {
		return "", fmt.Errorf("unable to find %s in PATH: %s", filename.ExecutableName, err)
	}
	return path, nil
}

// LookUserDir searches for the Vulnmap CLI executable in the  XDG_DATA_HOME/vulnmap-ls directory.
func (d *Discovery) LookUserDir() (string, error) {
	folder := userDirName
	path := filepath.Join(xdg.DataHome, folder, filename.ExecutableName)
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}
	return "", fmt.Errorf("unable to find %s in user directory", filename.ExecutableName)
}

// ExecutableName returns OS specific filename for Vulnmap CLI.
func (d *Discovery) ExecutableName(isUpdate bool) string {
	if isUpdate {
		return filename.ExecutableName + ".latest"
	}
	return filename.ExecutableName
}

// DownloadURL returns OS specific download url for Vulnmap CLI.
func (d *Discovery) DownloadURL(r *Release) (string, error) {
	if r == nil {
		return "", fmt.Errorf("release cannot be nil")
	}
	return r.downloadURL(), nil
}

// ChecksumURL returns OS specific checksum url for Vulnmap CLI.
func (d *Discovery) ChecksumURL(r *Release) (string, error) {
	if r == nil {
		return "", fmt.Errorf("release cannot be nil")
	}
	return r.checksumURL(), nil
}

// ChecksumInfo returns OS specific checksum information for Vulnmap CLI.
func (d *Discovery) ChecksumInfo(r *Release) (string, error) {
	if r == nil {
		return "", fmt.Errorf("release cannot be nil")
	}
	return r.checksumInfo(), nil
}

func (d *Discovery) LookConfigPath() (string, error) {
	cliPath := config.CurrentConfig().CliSettings().Path()
	if file, err := os.Stat(cliPath); err == nil {
		if !file.IsDir() {
			return cliPath, nil
		}
	}

	return "", fmt.Errorf("unable to find CLI in %s", cliPath)
}
