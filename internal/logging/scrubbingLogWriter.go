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

package logging

import (
	"strings"

	"github.com/rs/zerolog"
)

type scrubbingWriter struct {
	writer    zerolog.LevelWriter
	scrubDict map[string]bool
}

func (w *scrubbingWriter) WriteLevel(level zerolog.Level, p []byte) (n int, err error) {
	return w.writer.WriteLevel(level, w.scrub(p))
}

func NewScrubbingWriter(writer zerolog.LevelWriter, scrubDict map[string]bool) zerolog.LevelWriter {
	return &scrubbingWriter{
		writer:    writer,
		scrubDict: scrubDict,
	}
}

func (w *scrubbingWriter) Write(p []byte) (n int, err error) {
	return w.writer.Write(w.scrub(p))
}

func (w *scrubbingWriter) scrub(p []byte) []byte {
	s := string(p)
	for term := range w.scrubDict {
		s = strings.Replace(s, term, "***", -1)
	}
	return []byte(s)
}
