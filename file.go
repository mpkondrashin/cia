package main

import (
	"fmt"
	"os"
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
	Mime string
}

func NewFile(path string) (*File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("lstat: %w", err)
	}
	return NewFileWithInfo(path, info)
}

func NewFileWithInfo(path string, info os.FileInfo) (*File, error) {
	mime, err := MimeType(path)
	if err != nil {
		return nil, err
	}
	return &File{
		Path: path,
		Info: info,
		Mime: mime,
	}, nil
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
