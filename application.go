package main

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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
	tasks        chan string
	wg           sync.WaitGroup
	returnCode   int32
	pullInterval time.Duration
	accept       map[string]bool
}

func NewApplication(analyzer ddan.ClientInterace) *Application {
	return &Application{
		analyzer:     analyzer,
		maxFileSize:  50_000_000,
		tasks:        make(chan string),
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

func (a *Application) IncReturnCode() {
	_ = atomic.AddInt32(&a.returnCode, 1)
}

func (a *Application) ProcessFolder(folder string) error {
	log.Print(a)
	err := a.analyzer.Register(context.TODO())
	if err != nil {
		if !errors.Is(err, ddan.ErrAlreadyRegistered) {
			return fmt.Errorf("Analyzer Register: %w", err)
		}
	} else {
		log.Print("Registration complete")
	}
	a.StartDispatchers()
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
	close(a.tasks)
	a.wg.Wait()
	if a.returnCode > 0 {
		err = fmt.Errorf("Found %d inadmissible files", a.returnCode)
	}
	return nil

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
	log.Printf("ProcessFile(%s)", path)
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
			a.IncReturnCode()
		} else {
			log.Printf("Skip %d bytes file: %s", info.Size(), path)
		}
		return nil
	}
	a.tasks <- path
	return nil
}

func (a *Application) StartDispatchers() {
	tasks := 100
	a.wg.Add(tasks)
	for i := 0; i < tasks; i++ {
		go a.Dispatcher()
	}
}

func (a *Application) Dispatcher() {
	defer a.wg.Done()
	for path := range a.tasks {
		if a.CheckFile(path) {
			a.IncReturnCode()
		}
	}
}

func (a *Application) CheckFile(path string) bool {
	log.Printf("CheckFile %s", path)
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

// WaitForResult - wait for result from Analyzer for file defined by sha1
func (a *Application) WaitForResult(path, sha1 string) bool {
	for {
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
			a.SleepLong()
			continue
		case ddan.StatusProcessing:
			a.SleepShort()
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
}

// Pass - return whenever file should be accepted to pass
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

// SleepLong - sleep for long when file is still in the queue
func (a *Application) SleepLong() {
	a.SleepRandom(a.pullInterval)
}

// SleepShort - sleep for short when file is alredy being processed
func (a *Application) SleepShort() {
	a.SleepRandom(a.pullInterval / 4)
}

// SleepRandom - sleep for random time between d/2 and d
func (a *Application) SleepRandom(d time.Duration) {
	time.Sleep(d)
	//duration := rand.Int63n(int64(d / 2))
	//time.Sleep(time.Duration(duration) + d/2)
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
