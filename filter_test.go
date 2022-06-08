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

func TestLoadFilter(t *testing.T) {
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

/*
func TestFileHeader(t *testing.T) {
	testingFolder := "testing_filter"
	err := os.MkdirAll(testingFolder, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	fileName := "read_header.txt"
	filePath := filepath.Join(testingFolder, fileName)
	f, err := os.Create(filePath)
	if err != nil {
		t.Fatal(t)
	}
	for i := 0; i < 216; i++ {
		f.WriteString("0")
	}
	for i := 0; i < 10; i++ {
		f.WriteString("1")
	}
	f.Close()

		file := NewFile(filePath)
		header, err := file.Header()
		if err != nil {
			t.Fatal(err)
		}
		actualInt := len(header)
		expectedInt := 216
		if expectedInt != actualInt {
			t.Errorf("Expected %d but got %d", expectedInt, actualInt)
		}
		for i := 0; i < len(header); i++ {
			actualInt := int(header[i])
			expectedInt := int('0')
			if expectedInt != actualInt {
				t.Errorf("Expected %d but got %d", expectedInt, actualInt)
			}

		}
}
*/
func TestFileInfo(t *testing.T) {
	testingFolder := "testing_filter"
	err := os.MkdirAll(testingFolder, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	fileName := "info.txt"
	filePath := filepath.Join(testingFolder, fileName)
	/*	f, err := os.Create(filePath)
		if err != nil {
			t.Fatal(t)
		}
		for i := 0; i < 100; i++ {
			f.WriteString("0")
		}
		f.Close()
	*/
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
