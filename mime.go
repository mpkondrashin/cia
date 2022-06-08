package main

import (
	"fmt"
	"os/exec"
	"strings"
)

func MimeType(filePath string) (string, error) {
	options := []string{"--mime-type", "--brief", filePath}
	cmd := exec.Command("file", options...)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%s %v: %w", "file", options, err)
	}
	return strings.TrimRight(string(output), "\n"), nil
}
