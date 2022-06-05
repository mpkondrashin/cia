package main

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mpkondrashin/ddan"
)

func analyzerMockupClient(t *testing.T) (ddan.ClientInterace, func()) {
	AnalyzerURL := "127.0.0.1:8000"
	apiKey := "C7213F09-B399-4C71-9D1C-3A99905215E9"
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
	files := []string{
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
	for _, each := range files {
		filePath := filepath.Join(baseFolder, each)
		dir := filepath.Dir(filePath)
		err := os.MkdirAll(dir, 0o755)
		if err != nil {
			t.Fatal(err)
		}
		content := filepath.Base(each)
		content = content[:len(content)-len(filepath.Ext(content))]
		f, err := os.Create(filePath)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.WriteString(content)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
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
}

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
