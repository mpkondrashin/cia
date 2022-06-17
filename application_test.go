package main

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mpkondrashin/ddan"
)

func analyzerMockupClient(t *testing.T) (ddan.ClientInterace, func()) {
	AnalyzerURL := "127.0.0.1:8000"
	apiKey := "00000000-0000-0000-0000-000000000000"
	mockup := ddan.NewMockup(AnalyzerURL, apiKey)
	cerr := make(chan error)
	go mockup.Run(cerr)
	err := mockup.WaitToStart()
	if err != nil {
		t.Fatalf("Mockup did not start: %v", err)
	}

	URL, err := url.Parse("http://" + AnalyzerURL)
	if err != nil {
		t.Fatal(err)
	}

	stop := func() {
		err = mockup.Stop()
		if err != nil {
			t.Errorf("mockup.Stop(): %v", err)
		}
		select {
		case err = <-cerr:
			t.Logf("Mockup returned: %v", err)
		default:
			t.Errorf("Mockup did not returned anything")
		}
	}

	return ddan.NewClient("productName", "hostname").
		SetAnalyzer(URL, apiKey, false).
		SetSource("500", "sourceName").
		SetUUID("12341234-1234-1234-1234-123412341234"), stop

}

func prepairFolder(t *testing.T, baseFolder string) {
	t.Helper()
	paths := []string{
		"unsupported.txt",
		"no_risk_found.txt",
		"medium_risk.txt",
		"high_risk.txt",
		"folder/unsupported.txt",
		"folder/no_risk_found.txt",
		"folder/medium_risk.txt",
		"folder/high_risk.txt",
	}
	err := os.RemoveAll(baseFolder)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		filePath := filepath.Join(baseFolder, path)
		dir := filepath.Dir(filePath)
		err := os.MkdirAll(dir, 0o755)
		if err != nil {
			t.Fatal(err)
		}
		content := filepath.Base(path)
		content = content[:len(content)-len(filepath.Ext(content))]
		file, err := os.Create(filePath)
		if err != nil {
			t.Fatal(err)
		}
		_, err = file.WriteString(content)
		if err != nil {
			t.Fatal(err)
		}
		file.Close()
	}
}

func prepairBigFolder(t *testing.T, baseFolder string) {
	t.Helper()
	var layer func(string, int)
	layer = func(base string, level int) {
		for i := 0; i < 100; i++ {
			fileName := fmt.Sprintf("%0X.dat", i)
			filePath := filepath.Join(base, fileName)
			file, err := os.Create(filePath)
			if err != nil {
				t.Fatal(err)
			}
			_, err = file.WriteString(".")
			if err != nil {
				t.Fatal(err)
			}
			file.Close()
		}
		if level == 0 {
			return
		}
		for i := 0; i < 100; i++ {
			folderName := fmt.Sprintf("%0X", i)
			folderPath := filepath.Join(base, folderName)
			err := os.MkdirAll(folderPath, 0o755)
			if err != nil {
				t.Fatal(err)
			}
			layer(folderPath, level-1)
		}
	}
	err := os.RemoveAll(baseFolder)
	if err != nil {
		t.Fatal(err)
	}
	err = os.MkdirAll(baseFolder, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	layer(baseFolder, 1)
}

func TestApplication001(t *testing.T) {
	baseFolder := "testing/t001"
	prepairFolder(t, baseFolder)
	analyzer, stop := analyzerMockupClient(t)
	app := NewApplication(analyzer).SetPause(1 * time.Millisecond)
	for _, each := range verdictList {
		app.SetAction(each, true)
	}
	app.SetAction("highRisk", false)
	err := app.ProcessFolder(baseFolder)
	if err != nil {
		t.Fatal(err)
	}
	stop()
}

/*
func TestApplicationIgnore(t *testing.T) {
	baseFolder := "testing/t001"
	prepairFolder(t, baseFolder)
	analyzer, stop := analyzerMockupClient(t)
	app := NewApplication(analyzer).SetPause(1 * time.Millisecond)
	app.SetIgnore([]string{"*folder*"})
	err := app.ProcessFolder(baseFolder)
	if err != nil {
		t.Fatal(err)
	}
	stop()
}*/

func TestApplicationMaxFileSize(t *testing.T) {
	baseFolder := "testing/t001"
	prepairFolder(t, baseFolder)
	analyzer, stop := analyzerMockupClient(t)
	app := NewApplication(analyzer).SetPause(1 * time.Millisecond)
	app.SetMaxFileSize(10)
	err := app.ProcessFolder(baseFolder)
	if err != nil {
		t.Fatal(err)
	}
	stop()
}

func TestApplicationBigFolder(t *testing.T) {
	baseFolder := "testing/big"
	prepairBigFolder(t, baseFolder)
	analyzer, stop := analyzerMockupClient(t)
	app := NewApplication(analyzer).SetPause(1 * time.Millisecond)
	for _, each := range verdictList {
		app.SetAction(each, true)
	}
	app.SetAction("highRisk", false)
	err := app.ProcessFolder(baseFolder)
	if err != nil {
		t.Fatal(err)
	}
	stop()
}
