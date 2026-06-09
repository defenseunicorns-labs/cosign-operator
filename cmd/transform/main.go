package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/defenseunicorns-labs/cosign-operator/internal/transform"
)

const defaultAdmissionDeployment = "chart/templates/admission-deployment.yaml"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("transform", flag.ContinueOnError)
	fs.SetOutput(stderr)

	inputPath := fs.String("input", defaultAdmissionDeployment, "Helm template to transform")
	outputPath := fs.String("output", "", "output path; defaults to overwriting input")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "unexpected arguments: %v\n", fs.Args())
		return 2
	}

	info, err := os.Stat(*inputPath)
	if err != nil {
		fmt.Fprintf(stderr, "stat %s: %v\n", *inputPath, err)
		return 1
	}

	input, err := os.ReadFile(*inputPath)
	if err != nil {
		fmt.Fprintf(stderr, "read %s: %v\n", *inputPath, err)
		return 1
	}

	output, changed, err := transform.TransformAdmissionDeployment(input)
	if err != nil {
		fmt.Fprintf(stderr, "transform %s: %v\n", *inputPath, err)
		return 1
	}

	target := *outputPath
	if target == "" {
		target = *inputPath
	}
	if changed || target != *inputPath {
		if err := os.WriteFile(target, output, info.Mode().Perm()); err != nil {
			fmt.Fprintf(stderr, "write %s: %v\n", target, err)
			return 1
		}
	}

	if changed {
		fmt.Fprintf(stdout, "transformed %s\n", target)
	} else {
		fmt.Fprintf(stdout, "already transformed %s\n", target)
	}

	return 0
}
