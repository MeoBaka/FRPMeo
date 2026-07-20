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

// Package cmdutil holds the update and service commands, which frpc and frps
// share in full - only the binary name and the service description differ.
package cmdutil

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/fatedier/frp/pkg/util/selfupdate"
	"github.com/fatedier/frp/pkg/util/service"
	"github.com/fatedier/frp/pkg/util/version"
)

// Binary describes which of the two programs the commands are being built for.
type Binary struct {
	// Name is the service name and the command's own name, "frpc" or "frps".
	Name string
	// FileName is what the executable is called inside a release archive.
	FileName string
	// Description is shown by the service manager.
	Description string
	// ConfigFile points at the -c value, read when a service is installed.
	ConfigFile *string
}

// NewUpdateCmd builds the "update" command: it lists newer releases, and
// installs the newest when asked.
func NewUpdateCmd(b Binary) *cobra.Command {
	var (
		repo    string
		apply   bool
		restart bool
	)
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Check for a newer release, and install it with --apply",
		// A failure here is a runtime problem, not a usage mistake; printing
		// the whole flag list on top of it buries the actual message.
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
			defer cancel()

			current := version.Full()
			fmt.Printf("current: %s\n", current)

			releases, err := selfupdate.FetchReleases(ctx, repo)
			if err != nil {
				return err
			}
			newer := selfupdate.NewerThan(releases, current)
			if len(newer) == 0 {
				fmt.Println("already up to date")
				return nil
			}

			fmt.Printf("\n%d newer release(s):\n", len(newer))
			for _, r := range newer {
				name := r.Name
				if name == "" {
					name = r.TagName
				}
				line := fmt.Sprintf("  %-26s %s", name, r.PublishedAt.Local().Format("2006-01-02"))
				if r.Prerelease {
					line += "  (pre-release)"
				}
				fmt.Println(line)
			}
			latest := newer[0]
			fmt.Printf("\n%s\n", latest.HTMLURL)

			if !apply {
				fmt.Printf("\nrun '%s update --apply' to install %s\n", b.Name, latest.Version())
				return nil
			}

			fmt.Println()
			if err := selfupdate.Apply(ctx, latest, b.FileName, func(msg string) {
				fmt.Println("  " + msg)
			}); err != nil {
				return err
			}

			if !restart {
				fmt.Printf("\nrestart %s to run the new version\n", b.Name)
				return nil
			}
			fmt.Printf("\nrestarting service %q...\n", b.Name)
			if err := service.Restart(b.Name); err != nil {
				if errors.Is(err, service.ErrNotInstalled) {
					return fmt.Errorf("no %q service installed: restart manually, or install one with '%s service install'", b.Name, b.Name)
				}
				return err
			}
			fmt.Println("  restarted")
			return nil
		},
	}
	cmd.Flags().StringVar(&repo, "repo", selfupdate.DefaultRepo, "GitHub repository to check")
	cmd.Flags().BoolVar(&apply, "apply", false, "download and install the newest release")
	cmd.Flags().BoolVar(&restart, "restart", false, "with --apply, restart the installed service afterwards")
	return cmd
}

// NewServiceCmd builds the "service" command group: install, uninstall, start,
// stop, restart and status.
func NewServiceCmd(b Binary) *cobra.Command {
	cmd := &cobra.Command{
		Use:          "service",
		Short:        "Manage the " + b.Name + " system service (starts on boot)",
		SilenceUsage: true,
	}

	install := &cobra.Command{
		Use:          "install",
		Short:        "Install the service and set it to start on boot",
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			cfgFile := ""
			if b.ConfigFile != nil {
				cfgFile = *b.ConfigFile
			}
			if cfgFile == "" {
				return fmt.Errorf("specify the config to run with, e.g. '%s service install -c %s.toml'", b.Name, b.Name)
			}
			cfg, err := service.NewConfig(b.Name, b.Name, b.Description, cfgFile)
			if err != nil {
				return err
			}
			if err := service.Install(cfg); err != nil {
				return err
			}
			fmt.Printf("installed service %q\n", b.Name)
			fmt.Printf("  exec: %s %v\n", cfg.Exec, cfg.Args)
			fmt.Printf("  starts on boot, and restarts if it exits unexpectedly\n")
			fmt.Printf("\nstart it with: %s service start\n", b.Name)
			return nil
		},
	}

	uninstall := &cobra.Command{
		Use:          "uninstall",
		Short:        "Stop and remove the service",
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := service.Uninstall(b.Name); err != nil {
				return notInstalled(b, err)
			}
			fmt.Printf("removed service %q\n", b.Name)
			return nil
		},
	}

	start := &cobra.Command{
		Use:          "start",
		Short:        "Start the service",
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := service.Start(b.Name); err != nil {
				return notInstalled(b, err)
			}
			fmt.Printf("started %q\n", b.Name)
			return nil
		},
	}

	stop := &cobra.Command{
		Use:          "stop",
		Short:        "Stop the service",
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := service.Stop(b.Name); err != nil {
				return notInstalled(b, err)
			}
			fmt.Printf("stopped %q\n", b.Name)
			return nil
		},
	}

	restart := &cobra.Command{
		Use:          "restart",
		Short:        "Restart the service",
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := service.Restart(b.Name); err != nil {
				return notInstalled(b, err)
			}
			fmt.Printf("restarted %q\n", b.Name)
			return nil
		},
	}

	status := &cobra.Command{
		Use:          "status",
		Short:        "Show whether the service is installed and running",
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			st, err := service.QueryStatus(b.Name)
			if err != nil {
				return err
			}
			fmt.Printf("%s: %s\n", b.Name, st)
			if !st.Installed {
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.AddCommand(install, uninstall, start, stop, restart, status)
	return cmd
}

func notInstalled(b Binary, err error) error {
	if errors.Is(err, service.ErrNotInstalled) {
		return fmt.Errorf("no %q service installed (install one with '%s service install -c %s.toml')", b.Name, b.Name, b.Name)
	}
	return err
}
