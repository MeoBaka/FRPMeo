// Copyright 2026 The frp Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package configmgmt

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"

	"github.com/pelletier/go-toml/v2"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

// ReadCommonConfig pulls the client-level settings out of a config file, so a
// form can show them as fields rather than as text.
func ReadCommonConfig(content string) (*v1.ClientCommonConfig, error) {
	m, err := tomlToMap(content)
	if err != nil {
		return nil, err
	}
	cfg := &v1.ClientCommonConfig{}
	if err := mapToStruct(m, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// tomlToMap and the two helpers below route everything through json, which is
// how frp itself loads a config file - see config.LoadConfigure. It matters
// because these structs are tagged for json and not for toml: marshalled
// straight to toml they come out under their Go field names, so "serverAddr"
// would be written as "ServerAddr" and read back by nobody.
func tomlToMap(content string) (map[string]any, error) {
	out := map[string]any{}
	if strings.TrimSpace(content) == "" {
		return out, nil
	}
	if err := toml.Unmarshal([]byte(content), &out); err != nil {
		return nil, fmt.Errorf("%w: config is not valid toml: %v", ErrInvalidArgument, err)
	}
	return out, nil
}

func mapToStruct(m map[string]any, v any) error {
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	return nil
}

func structToMap(v any) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	return out, nil
}

// MergeCommonConfig writes the client-level settings back into a config file
// and returns the new text.
//
// Merged through a map rather than by re-serializing the whole file from a
// struct, and that is the important part. A config file holds more than this
// struct knows about - the proxies and visitors below it, and any key belonging
// to a newer version of frp than the one doing the writing. Round-tripping
// through the struct would silently drop every one of them; replacing only the
// client-level keys leaves them exactly as they were.
//
// What is not preserved is comments and key order, which toml marshaling
// cannot carry. Anyone who annotates their config should edit it as text
// instead - which is why the raw editor is still there.
func MergeCommonConfig(content string, cfg *v1.ClientCommonConfig) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("%w: no config given", ErrInvalidArgument)
	}

	file, err := tomlToMap(content)
	if err != nil {
		return "", err
	}

	// omitempty decides what a cleared field means: absent from the result
	// rather than present as a zero, because a config saying serverPort = 0 is
	// worse than one saying nothing.
	incoming, err := structToMap(cfg)
	if err != nil {
		return "", err
	}

	// Every key this struct owns is replaced or removed; everything else in the
	// file is left alone.
	for _, key := range commonConfigKeys() {
		if v, ok := incoming[key]; ok {
			file[key] = v
		} else {
			delete(file, key)
		}
	}

	out, err := toml.Marshal(tidy(file))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}

	// Parse what is about to be written. A file that does not load is a client
	// that will not come back, and finding that out at the next restart is too
	// late to be useful.
	if _, err := ReadCommonConfig(string(out)); err != nil {
		return "", err
	}
	return string(out), nil
}

// tidy repairs what the json hop does to a config on its way back to toml.
//
// Two things go wrong there. Every number becomes a float64, so a port would be
// written as 7000.0 - which frp reads back correctly, having taken the same
// route, but which is wrong to anything else looking at the file and wrong to
// anyone reading it. And a struct with no omitempty on its nested fields
// contributes an empty table for every one of them, so a small config grows a
// crop of bare [auth.oidc] and [transport.quic] headers that say nothing.
//
// Whole floats become integers; empty tables are dropped. An empty list is
// kept: writing one down is a way of saying "none", and that is a different
// statement from leaving the key out.
func tidy(v any) any {
	switch t := v.(type) {

	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			c := tidy(val)
			if m, ok := c.(map[string]any); ok && len(m) == 0 {
				continue
			}
			out[k] = c
		}
		return out

	case []any:
		out := make([]any, 0, len(t))
		for _, val := range t {
			out = append(out, tidy(val))
		}
		return out

	case float64:
		if t == math.Trunc(t) && !math.IsInf(t, 0) {
			return int64(t)
		}
		return t

	default:
		return v
	}
}

// commonConfigKeys lists the top-level keys ClientCommonConfig owns, read off
// the struct so a field added later is covered without anyone remembering.
func commonConfigKeys() []string {
	t := reflect.TypeFor[v1.ClientCommonConfig]()
	keys := make([]string, 0, t.NumField())
	for i := range t.NumField() {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if name != "" && name != "-" {
			keys = append(keys, name)
		}
	}
	return keys
}

// CommonConfigJSON is what the api hands a form: the settings themselves, plus
// the file they came from so a caller can tell an empty config from a missing
// one.
type CommonConfigJSON struct {
	Common *v1.ClientCommonConfig `json:"common"`
}

// DecodeCommonConfig reads the form's submission.
func DecodeCommonConfig(body []byte) (*v1.ClientCommonConfig, error) {
	var in CommonConfigJSON
	if err := json.Unmarshal(body, &in); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	if in.Common == nil {
		return nil, fmt.Errorf("%w: missing common config", ErrInvalidArgument)
	}
	return in.Common, nil
}
