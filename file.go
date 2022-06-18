/*

Check It All (c) 2022 by Michael Kondrashin mkondrashin@gmail.com

file.go - file operations

*/

package main

import (
	"crypto/sha1" //nolint
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

type File struct {
	Path string
	Info os.FileInfo
	mime string
}

func (f *File) String() string {
	mime, err := f.Mime()
	if err != nil {
		mime = err.Error()
	}
	return fmt.Sprintf("[%s] %s", mime, f.Path)
}

// NewFile — create new File struct with path.
func NewFile(path string) (*File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("lstat: %w", err)
	}
	return NewFileWithInfo(path, info), nil
}

// NewFileWithInfo — create new File struct with path and FileInfo.
func NewFileWithInfo(path string, info os.FileInfo) *File {
	return &File{
		Path: path,
		Info: info,
		mime: "",
	}
}

// Mime - return MIME type of file.
func (f *File) Mime() (string, error) {
	if f.mime == "" {
		options := []string{"--mime-type", "--brief", f.Path}
		cmd := exec.Command("file", options...)
		output, err := cmd.Output()
		if err != nil {
			return "", fmt.Errorf("%s %v: %w", "file", options, err)
		}
		f.mime = strings.TrimRight(string(output), "\n")
	}
	return f.mime, nil
}

// FileSHA1 - return SHA1 for file.
func (f *File) Sha1() (string, error) {
	input, err := os.Open(f.Path)
	if err != nil {
		return "", fmt.Errorf("calculating SHA1 for file %s: %w", f.Path, err)
	}
	hash := sha1.New() //nolint
	_, err = io.Copy(hash, input)
	if err != nil {
		return "", fmt.Errorf("calculating SHA1 for file %s: %w", f.Path, err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
