package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

var (
	filterYaml = `# test data
rules:
#  - submit: false
#    type: path
#    value: '*.txt'
#  - submit: false
#    type: path
#    value: '*.tmp'
  - submit: true
    type: mime
    value: 'application/*zip'
  - submit: true
    type: mime
    value: 'application/x*exe*'
  - submit: true
    type: mime
    value: '*shellscript'	
`
)

/*
archive.gz:  application/gzip
archive.zip: application/zip
filter.yaml: text/plain
info.txt:    text/plain
python.py:   text/x-script.python
tiny:        application/x-mach-binary
tiny.c:      text/x-c
win32.exe:   application/x-dosexec
*/

func TestFilterLoad(t *testing.T) {
	testingFolder := "testing_filter"
	/*	err := os.MkdirAll(testingFolder, 0o755)
		if err != nil {
			t.Fatal(err)
		} */
	filterFileName := "filter.yaml"
	filterFilePath := filepath.Join(testingFolder, filterFileName)
	err := ioutil.WriteFile(filterFilePath, []byte(filterYaml), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	filter, err := LoadFilter(filterFilePath)
	if err != nil {
		t.Fatal(err)
	}

	checkFile := func(fileName string, expected bool) {
		filePath := filepath.Join(testingFolder, fileName)
		file, err := NewFile(filePath)
		if err != nil {
			t.Fatal(err)
		}
		submit, err := filter.CheckFile(file)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("Submit=%v: %s", submit, fileName)
		mime, err := MimeType(filePath)
		if err != nil {
			t.Fatal(mime)
		}
		if submit != expected {
			t.Errorf("Expected %v, but got %v for %s (%s)", expected, submit, filePath, mime)
		}
	}
	checkFile("archive.gz", true)
	checkFile("archive.zip", true)
	checkFile("info.txt", false)
	checkFile("python.py", false)
	checkFile("hello", true)
	checkFile("shell.sh", true)
	checkFile("tiny.c", false)
	checkFile("win32.exe", true)
	checkFile("tiny.c", false)
}

func TestFileInfo(t *testing.T) {
	testingFolder := "testing_filter"
	err := os.MkdirAll(testingFolder, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	fileName := "info.txt"
	filePath := filepath.Join(testingFolder, fileName)
	file, err := NewFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	expectedInt := 100
	actualInt := int(file.Info.Size())
	if expectedInt != actualInt {
		t.Errorf("Expected %d but got %d", expectedInt, actualInt)
	}
}
