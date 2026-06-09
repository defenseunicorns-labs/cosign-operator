package transform

import (
	"fmt"
	"strings"
)

const (
	deploymentKind = "kind: Deployment"
	daemonSetKind  = "kind: DaemonSet"
	rootSpec       = "spec:"
	replicasKey    = "  replicas:"
	updateKey      = "  updateStrategy:"
	selectorKey    = "  selector:"
)

type specMarkers struct {
	replicas int
	update   int
	selector int
}

// TransformAdmissionDeployment converts Pepr's Helm-templated admission
// Deployment into a DaemonSet without parsing the template as plain YAML.
func TransformAdmissionDeployment(input []byte) ([]byte, bool, error) {
	lines := strings.SplitAfter(string(input), "\n")

	deploymentIdx := findRootLine(lines, deploymentKind)
	daemonSetIdx := findRootLine(lines, daemonSetKind)

	if deploymentIdx == -1 {
		if daemonSetIdx != -1 {
			if err := validateDaemonSet(lines, daemonSetIdx); err != nil {
				return nil, false, err
			}
			return input, false, nil
		}
		return nil, false, fmt.Errorf("expected root %q", deploymentKind)
	}
	if daemonSetIdx != -1 {
		return nil, false, fmt.Errorf("found both root %q and %q", deploymentKind, daemonSetKind)
	}

	specIdx := findRootSpecAfter(lines, deploymentIdx)
	if specIdx == -1 {
		return nil, false, fmt.Errorf("expected root %q after %q", rootSpec, deploymentKind)
	}

	markers := scanRootSpec(lines, specIdx)
	if markers.replicas == -1 {
		return nil, false, fmt.Errorf("expected top-level %q under root spec", strings.TrimSpace(replicasKey))
	}
	if markers.selector == -1 {
		return nil, false, fmt.Errorf("expected top-level %q under root spec", strings.TrimSpace(selectorKey))
	}
	if markers.replicas > markers.selector {
		return nil, false, fmt.Errorf("expected top-level spec.replicas before spec.selector")
	}
	if markers.update != -1 {
		return nil, false, fmt.Errorf("refusing to add duplicate top-level %q", strings.TrimSpace(updateKey))
	}

	replaceLine(&lines[deploymentIdx], daemonSetKind)
	eol := preferredEOL(lines, markers.selector)

	out := make([]string, 0, len(lines)+1)
	for i, line := range lines {
		if i == markers.replicas {
			continue
		}
		if i == markers.selector {
			out = append(out, updateKey+eol, "    type: RollingUpdate"+eol)
		}
		out = append(out, line)
	}

	return []byte(strings.Join(out, "")), true, nil
}

func validateDaemonSet(lines []string, kindIdx int) error {
	specIdx := findRootSpecAfter(lines, kindIdx)
	if specIdx == -1 {
		return fmt.Errorf("found root %q but missing root %q", daemonSetKind, rootSpec)
	}

	markers := scanRootSpec(lines, specIdx)
	if markers.replicas != -1 {
		return fmt.Errorf("found root %q but top-level spec.replicas remains", daemonSetKind)
	}
	if markers.update == -1 {
		return fmt.Errorf("found root %q but missing top-level spec.updateStrategy", daemonSetKind)
	}
	if markers.selector == -1 {
		return fmt.Errorf("found root %q but missing top-level spec.selector", daemonSetKind)
	}
	if markers.update > markers.selector {
		return fmt.Errorf("found root %q but spec.updateStrategy must be before spec.selector", daemonSetKind)
	}

	return nil
}

func findRootLine(lines []string, want string) int {
	for i, line := range lines {
		body, _ := splitEOL(line)
		if body == want {
			return i
		}
	}
	return -1
}

func findRootSpecAfter(lines []string, start int) int {
	for i := start + 1; i < len(lines); i++ {
		body, _ := splitEOL(lines[i])
		if body == rootSpec {
			return i
		}
	}
	return -1
}

func scanRootSpec(lines []string, specIdx int) specMarkers {
	markers := specMarkers{replicas: -1, update: -1, selector: -1}

	for i := specIdx + 1; i < len(lines); i++ {
		body, _ := splitEOL(lines[i])
		if isRootYAMLKey(body) {
			break
		}

		switch {
		case strings.HasPrefix(body, replicasKey):
			markers.replicas = i
		case body == updateKey:
			markers.update = i
		case body == selectorKey:
			markers.selector = i
		}
	}

	return markers
}

func isRootYAMLKey(body string) bool {
	if body == "" || strings.HasPrefix(body, " ") || strings.HasPrefix(body, "\t") {
		return false
	}
	if strings.HasPrefix(body, "{{") || strings.HasPrefix(body, "---") {
		return false
	}
	return strings.Contains(body, ":")
}

func replaceLine(line *string, body string) {
	_, eol := splitEOL(*line)
	*line = body + eol
}

func preferredEOL(lines []string, near int) string {
	if near >= 0 && near < len(lines) {
		if _, eol := splitEOL(lines[near]); eol != "" {
			return eol
		}
	}
	for _, line := range lines {
		if _, eol := splitEOL(line); eol != "" {
			return eol
		}
	}
	return "\n"
}

func splitEOL(line string) (string, string) {
	if strings.HasSuffix(line, "\r\n") {
		return strings.TrimSuffix(line, "\r\n"), "\r\n"
	}
	if strings.HasSuffix(line, "\n") {
		return strings.TrimSuffix(line, "\n"), "\n"
	}
	return line, ""
}
