package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

//const HeaderSize = 216

//type Header []byte

//var (
//	ErrFileTooSmall = errors.New("file too small")

//	ErrUnknownFileType = errors.New("unknown file type")
//)

type File struct {
	Path string
	//	header Header
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

func NewFile(path string) (*File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("lstat: %w", err)
	}
	return NewFileWithInfo(path, info), nil
}

func NewFileWithInfo(path string, info os.FileInfo) *File {
	//mime, err := MimeType(path)
	//if err != nil {
	//	return nil, err
	//}
	return &File{
		Path: path,
		Info: info,
		mime: "",
	}
}
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

// FileSHA1 - return SHA1 for file
func (f *File) Sha1() (string, error) {
	input, err := os.Open(f.Path)
	if err != nil {
		return "", err
	}
	hash := sha1.New()
	_, err = io.Copy(hash, input)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

/*
func (f *File) Header() (Header, error) {
	if f.header == nil {
		file, err := os.Open(f.path)
		if err != nil {
			return nil, fmt.Errorf("Read header: %w", err)
		}
		defer file.Close()
		f.header = make(Header, HeaderSize)
		n, err := file.Read(f.header)
		if err != nil {
			return nil, fmt.Errorf("Read header: %w", err)
		}
		if n < HeaderSize {
			return nil, fmt.Errorf("Read header: %w: %s", ErrFileTooSmall, f.path)
		}
	}
	return f.header, nil
}
*/
/*
func (f *File) Info() (info os.FileInfo, err error) {
	if f.info == nil {
		f.info, err = os.Lstat(f.path)
		if err != nil {
			return nil, fmt.Errorf("lstat: %w", err)
		}
	}
	return f.info, nil
}

func (f *File) Mime() (mime string, err error) {
	if len(f.mime) == 0 {
		f.mime, err = MimeType(f.path)
		if err != nil {
			return "", err
		}
	}
	return f.mime, nil
}
*/
