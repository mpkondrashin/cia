package main

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/danwakefield/fnmatch"

	"github.com/mpkondrashin/ddan"
)

var verdictList = [...]string{
	"highRisk",
	"mediumRisk",
	"lowRisk",
	"error",
	"unscannable",
	"timeout",
	"bigFile",
}

type Application struct {
	analyzer     ddan.ClientInterace
	maxFileSize  int
	ignore       []string
	wg           sync.WaitGroup
	result       chan struct{}
	pullInterval time.Duration
	accept       map[string]bool
}

func NewApplication(analyzer ddan.ClientInterace) *Application {
	return &Application{
		analyzer:     analyzer,
		maxFileSize:  50_000_000,
		result:       make(chan struct{}, 1000000),
		pullInterval: 60 * time.Second,
		accept:       make(map[string]bool),
	}
}

func (a *Application) SetIgnore(ignore []string) *Application {
	a.ignore = ignore
	return a
}

func (a *Application) SetPause(pullInterval time.Duration) *Application {
	a.pullInterval = pullInterval
	return a
}

func (a *Application) SetAction(actionName string, pass bool) *Application {
	a.accept[actionName] = pass
	return a
}

func (a *Application) SetMaxFileSize(maxFileSize int) *Application {
	a.maxFileSize = maxFileSize
	return a
}

func (a *Application) ProcessFolder(folder string) error {
	log.Print(a)
	err := a.analyzer.Register(context.TODO())
	if err != nil {
		return fmt.Errorf("Analyzer Register: %w", err)
	}
	log.Print("Registration complete")
	log.Printf("Process folder: %s", folder)
	start := time.Now()
	count := 0
	err = filepath.Walk(folder, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		count++
		if start.After(time.Now().Add(10 * time.Second)) {
			start = time.Now()
			log.Printf("Found %d files", count)
		}
		return a.ProcessFile(path, info)
	})
	if err != nil {
		return err
	}
	log.Printf("Scan complete. Found %d files. Waiting for analysis results", count)
	a.wg.Wait()
	return a.ProcessResults()
}

func (a *Application) Ignore(path string) (matched bool, err error) {
	for _, pattern := range a.ignore {
		matched = fnmatch.Match(pattern, path, 0)
		if matched {
			return
		}
	}
	return false, nil
}

func (a *Application) ProcessFile(path string, info os.FileInfo) error {
	//log.Printf("ProcessFile(%s)", path)
	matched, err := a.Ignore(path)
	if err != nil {
		log.Fatal(err)
	}
	if matched {
		log.Printf("Ignore: %s", path)
		return nil
	}
	if info.Size() > int64(a.maxFileSize) {
		if !a.accept["bigFile"] {
			log.Printf("Too big (%d) bytes file: %s", info.Size(), path)
			a.result <- struct{}{}
		} else {
			log.Printf("Skip %d bytes file: %s", info.Size(), path)
		}
		return nil
	}
	a.wg.Add(1)
	go a.ProcessGoroutine(path)
	return nil
}

func (a *Application) ProcessResults() (err error) {
	close(a.result)
	if len(a.result) > 0 {
		err = fmt.Errorf("Found %d inadmissible files", len(a.result))
	}
	return
}

func (a *Application) ProcessGoroutine(path string) {
	defer a.wg.Done()
	if a.CheckFile(path) {
		a.result <- struct{}{}
	}
}

func (a *Application) CheckFile(path string) bool {
	//log.Printf("CheckFile %s", path)
	sha1, err := FileSHA1(path)
	if err != nil {
		log.Fatal(err)
	}

	sha1List := []string{sha1}
	duplicates, err := a.analyzer.CheckDuplicateSample(context.TODO(), sha1List, 0)
	if err != nil {
		log.Fatal(err)
	}

	if len(duplicates) == 0 || !strings.EqualFold(duplicates[0], sha1) {
		err = a.analyzer.UploadSample(context.TODO(), path, sha1)
		if err != nil {
			log.Fatal(err)
		}
	}
	log.Printf("Uploaded %s", path)
	return a.WaitForResult(path, sha1)
}

/*
func (a *Application) __checkDuplicate(sha1 string) ([]string, error) {
	sha1List := []string{sha1}
	for i := 0; i < 2; i++ {
		duplicates, err := a.analyzer.CheckDuplicateSample(context.TODO(), sha1List, 0)
		if err != nil {
			var ddanErr *ddan.APIError
			if !errors.As(err, &ddanErr) || ddanErr.Response != ddan.ResponseNotRegistered {
				return nil, err
			}
			log.Print("Not Registered")
			err := a.analyzer.Register(context.TODO())
			if err != nil {
				return nil, err
			}
			log.Print("Registration complete")
			continue
		}
		return duplicates, nil
	}
	return nil, fmt.Errorf("Count not register")
}
*/
func (a *Application) WaitForResult(path, sha1 string) bool {
	for {
		a.Sleep()
		sha1List := []string{sha1}
		briefReport, err := a.analyzer.GetBriefReport(context.TODO(), sha1List)
		if err != nil {
			log.Fatal(err)
		}
		report := briefReport.Reports[0]
		//log.Printf("%s (%d): %v", path, count, report)
		switch report.SampleStatus {
		case ddan.StatusNotFound:
			log.Fatalf("Not found by Analyzer: %v (%s)", sha1, path)
		case ddan.StatusArrived:
			continue
		case ddan.StatusProcessing:
			continue
		case ddan.StatusError:
			fallthrough
		case ddan.StatusTimeout:
			log.Printf("%v for %v", report.SampleStatus, path)
			fallthrough
		case ddan.StatusDone:
			log.Printf("%v: %s", report.RiskLevel, path)
			return a.Pass(report)
		default:
			log.Fatalf("Unexpected status value: %v", report.SampleStatus)
		}
	}
	return false
}

// BriefReportVerdict - get vedrict from BriefReport
func (a *Application) Pass(b ddan.BriefReport) bool {
	switch b.SampleStatus {
	case ddan.StatusNotFound, ddan.StatusArrived, ddan.StatusProcessing:
		log.Fatal(ddan.NotReadyError(ddan.StatusCodeNames[b.SampleStatus]))
		return true
	case ddan.StatusDone:
		switch b.RiskLevel {
		case ddan.RatingUnsupported:
			return a.accept["unscannable"]
		case ddan.RatingNoRiskFound:
			return true
		case ddan.RatingLowRisk:
			return a.accept["lowRisk"]
		case ddan.RatingMediumRisk:
			return a.accept["mediumRisk"]
		case ddan.RatingHighRisk:
			return a.accept["highRisk"]
		default:
			log.Fatalf("Unknown RiskLevel: %d", b.RiskLevel)
		}
	case ddan.StatusError:
		return a.accept["error"]
	case ddan.StatusTimeout:
		return a.accept["timeout"]
	}
	return false
}

// FileSHA1 - return SHA1 for file
func FileSHA1(filePath string) (string, error) {
	input, err := os.Open(filePath)
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

func (a *Application) Sleep() {
	duration := rand.Int63n(int64(a.pullInterval))
	time.Sleep(time.Duration(duration))
}
