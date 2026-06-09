package transform

import (
	"os"
	"strings"
	"testing"
)

func TestTransformAdmissionDeployment(t *testing.T) {
	input := readFixture(t, "testdata/admission-deployment.input.yaml")
	want := readFixture(t, "testdata/admission-deployment.golden.yaml")

	got, changed, err := TransformAdmissionDeployment(input)
	if err != nil {
		t.Fatalf("TransformAdmissionDeployment() error = %v", err)
	}
	if !changed {
		t.Fatal("TransformAdmissionDeployment() changed = false, want true")
	}
	if string(got) != string(want) {
		t.Fatalf("TransformAdmissionDeployment() mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestTransformAdmissionDeploymentAlreadyTransformed(t *testing.T) {
	input := readFixture(t, "testdata/admission-deployment.golden.yaml")

	got, changed, err := TransformAdmissionDeployment(input)
	if err != nil {
		t.Fatalf("TransformAdmissionDeployment() error = %v", err)
	}
	if changed {
		t.Fatal("TransformAdmissionDeployment() changed = true, want false")
	}
	if string(got) != string(input) {
		t.Fatal("TransformAdmissionDeployment() changed already-transformed input")
	}
}

func TestTransformAdmissionDeploymentMissingPatterns(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name: "missing kind",
			input: strings.Join([]string{
				"apiVersion: apps/v1",
				"spec:",
				"  replicas: 2",
				"  selector:",
				"",
			}, "\n"),
			wantErr: `expected root "kind: Deployment"`,
		},
		{
			name: "missing replicas",
			input: strings.Join([]string{
				"apiVersion: apps/v1",
				"kind: Deployment",
				"spec:",
				"  selector:",
				"",
			}, "\n"),
			wantErr: `expected top-level "replicas:"`,
		},
		{
			name: "missing selector",
			input: strings.Join([]string{
				"apiVersion: apps/v1",
				"kind: Deployment",
				"spec:",
				"  replicas: 2",
				"",
			}, "\n"),
			wantErr: `expected top-level "selector:"`,
		},
		{
			name: "partial daemonset",
			input: strings.Join([]string{
				"apiVersion: apps/v1",
				"kind: DaemonSet",
				"spec:",
				"  selector:",
				"",
			}, "\n"),
			wantErr: "missing top-level spec.updateStrategy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := TransformAdmissionDeployment([]byte(tt.input))
			if err == nil {
				t.Fatal("TransformAdmissionDeployment() error = nil, want error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("TransformAdmissionDeployment() error = %q, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func readFixture(t *testing.T, path string) []byte {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	return data
}
