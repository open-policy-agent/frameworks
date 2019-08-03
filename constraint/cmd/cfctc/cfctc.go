package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/golang/glog"
	_ "github.com/golang/glog"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/open-policy-agent/frameworks/constraint/pkg/compiler/regorewriter"
)

var rootCmd = &cobra.Command{
	Use:   "cfctc",
	Short: "cfctc is the constraint framework constraint template compiler",
	Long: `
Example usage for transforming the forseti-security/policy-library constraints:
git clone git@github.com:forseti-security/policy-library.git
go run ./cmd/cfctc/cfctc.go \
  --ct policy-library/validator \
  --lib policy-library/lib \
  --input ./policy-library \
  --output ./policy-library-rewrite \
  --pkgPrefix x.y.z \
  --alsologtostderr
opa test -v rewrite/lib/ rewrite/validator/
meld policy-library/lib/ rewrite/lib/
meld policy-library/validator/ rewrite/validator/
`,
	Run: rootCmdFn,
}

var (
	cts       []string
	libs      []string
	pkgPrefix string
	oldRoot   string
	newRoot   string
)

func init() {
	rootCmd.Flags().StringSliceVar(
		&cts, "ct", nil, "The rego for the constraint template body")
	rootCmd.Flags().StringSliceVar(
		&libs, "lib", nil, "Libs associated with the rego, can be file or directory")
	rootCmd.Flags().StringVar(
		&pkgPrefix, "pkgPrefix", "", "The new prefix to insert into the package path")
	rootCmd.Flags().StringVarP(
		&oldRoot, "input", "i", "", "The input 'root' directory, outputs will be")
	rootCmd.Flags().StringVarP(
		&newRoot, "output", "o", "", "The output 'root' directory, outputs will be")
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
}

func compileSrcs(
	cts []string,
	libs []string,
	newPkgPrefix string,
	oldRoot string,
	newRoot string) error {
	if len(cts) == 0 && len(libs) == 0 {
		return errors.Errorf("must specify --ct or --lib or both")
	}
	if (oldRoot == "") != (newRoot == "") {
		return errors.Errorf("--input and --output must be empty or non emtpy together")
	}

	regoRewriter, err := regorewriter.New(
		regorewriter.NewPackagePrefixer(newPkgPrefix),
		[]string{
			"data.lib",
			"data.validator.gcp.lib",
		},
		[]string{
			"data.inventory",
		},
	)

	if err != nil {
		return err
	}

	for _, ct := range cts {
		if err := regoRewriter.AddBaseFromFs(ct); err != nil {
			return err
		}
	}

	for _, libPath := range libs {
		if err := regoRewriter.AddLibFromFs(libPath); err != nil {
			return err
		}
	}

	srcs, err := regoRewriter.Rewrite()
	if err != nil {
		return err
	}

	if oldRoot != "" && newRoot != "" {
		if err := srcs.Reparent(oldRoot, newRoot); err != nil {
			return err
		}
		if err := srcs.Write(); err != nil {
			return err
		}
	}

	glog.Info("SUCCESS!")
	return nil
}

func rootCmdFn(cmd *cobra.Command, args []string) {
	err := compileSrcs(cts, libs, pkgPrefix, oldRoot, newRoot)
	if err != nil {
		fmt.Printf("%+v\n", err)
		os.Exit(1)
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("%+v\n", err)
		os.Exit(1)
	}
}
