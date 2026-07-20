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

package main

import (
	"runtime"

	"github.com/fatedier/frp/pkg/util/cmdutil"
)

func frpsBinary() cmdutil.Binary {
	name := "frps"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return cmdutil.Binary{
		Name:        "frps",
		FileName:    name,
		Description: "frp server",
		ConfigFile:  &cfgFile,
	}
}

func init() {
	rootCmd.AddCommand(cmdutil.NewUpdateCmd(frpsBinary()))
	rootCmd.AddCommand(cmdutil.NewServiceCmd(frpsBinary()))
}
