package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mpkondrashin/ddan"
)

var ErrInadmissibleFiles = errors.New("inadmissible files")

var VerdictList = [...]string{
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
	prescanJobs  int
	submitJobs   int
	filter       *Filter
	prescan      chan *File
	prescanWg    sync.WaitGroup
	submit       chan *File
	submitWg     sync.WaitGroup
	returnCode   int32
	pullInterval time.Duration
	accept       map[string]bool
	skipFolders  []string
}

func (a *Application) String() string {
	return fmt.Sprintf("Application{%v; maxFileSize: %d; jobs: %d; filter: %v; pullInterval: %v; accept: %v}",
		a.analyzer, a.maxFileSize, a.submitJobs, a.filter, a.pullInterval, a.accept)
}

// NewApplication - create application struct
func NewApplication(analyzer ddan.ClientInterace) *Application {
	return &Application{
		analyzer:     analyzer,
		maxFileSize:  50_000_000,
		prescan:      make(chan *File),
		submit:       make(chan *File),
		pullInterval: 60 * time.Second,
		accept:       make(map[string]bool),
	}
}

// SetPause - set time to wait between pulling results from Analyzer
func (a *Application) SetPause(pullInterval time.Duration) *Application {
	a.pullInterval = pullInterval
	return a
}

// SetAction - set action to giver risk level
func (a *Application) SetAction(riskLevel string, pass bool) *Application {
	a.accept[riskLevel] = pass
	return a
}

// SetPrescanJobs - number of goroutines to implement prescan
func (a *Application) SetPrescanJobs(jobs int) *Application {
	a.prescanJobs = jobs
	return a
}

// SetSubmitJobs - number of goroutines to submit files to analyzer and wait for result
func (a *Application) SetSubmitJobs(jobs int) *Application {
	a.submitJobs = jobs
	return a
}

// SetMaxFileSize - set maximum file size to submit to analyzer
func (a *Application) SetMaxFileSize(maxFileSize int) *Application {
	a.maxFileSize = maxFileSize
	return a
}

// SetFilter - set Filter struct
func (a *Application) SetFilter(filter *Filter) *Application {
	a.filter = filter
	return a
}

// SetSkipFolders - set list of folders to skip
func (a *Application) SetSkipFolders(skipFolders []string) *Application {
	a.skipFolders = skipFolders
	return a
}

// IncReturnCode - increment number of malicious files by 1
func (a *Application) IncReturnCode() {
	_ = atomic.AddInt32(&a.returnCode, 1)
}

// Run - execute all operations
func (a *Application) Run(folder string) error {
	startTime := time.Now()
	log.Print(a)
	err := a.analyzer.Register(context.TODO())
	if err != nil {
		if !errors.Is(err, ddan.ErrAlreadyRegistered) {
			return fmt.Errorf("analyzer register: %w", err)
		}
	} else {
		log.Print("Registration complete")
	}
	a.StartDispatchers()
	err = a.WalkFolder(folder)
	if err != nil {
		log.Fatal(err)
	}
	close(a.prescan)
	a.prescanWg.Wait()
	close(a.submit)
	a.submitWg.Wait()
	duration := time.Since(startTime)
	log.Printf("Operation time: %v", duration.Round(time.Second))
	if a.returnCode > 0 {
		return fmt.Errorf("Found %d %w", a.returnCode, ErrInadmissibleFiles) //nolint
	}
	return nil
}

// WalkFolder - recursively process all files in given folders
func (a *Application) WalkFolder(folder string) error {
	log.Printf("Process folder: %s", folder)
	count := 0
	err := filepath.Walk(folder, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&os.ModeDir != 0:
			if a.ShouldSkipFolder(path) {
				return filepath.SkipDir
			}
			return nil
		case info.Mode()&os.ModeSymlink != 0:
			log.Printf("Ignore symlink file: %s", path)
			return nil
		case info.Mode()&(os.ModeDevice|fs.ModeCharDevice) != 0:
			log.Printf("Ignore device file: %s", path)
			return nil
		case info.Mode()&os.ModeNamedPipe != 0:
			log.Printf("Ignore named pipe file: %s", path)
			return nil
		case info.Mode()&os.ModeSocket != 0:
			log.Printf("Ignore socket file: %s", path)
			return nil
		case info.Mode()&os.ModeIrregular != 0:
			log.Printf("Ignore irregular file: %s", path)
			return nil
		}
		count++
		file := NewFileWithInfo(path, info)
		a.prescan <- file
		return nil
	})
	if err != nil {
		return fmt.Errorf("processing %s folder: %w", folder, err)
	}
	log.Printf("Scan complete. Found %d files. Waiting for analysis results", count)
	return nil
}

// ShouldSkipFolder - folders to skip at all
func (a *Application) ShouldSkipFolder(folder string) bool {
	for _, each := range a.skipFolders {
		if strings.HasPrefix(folder, each) {
			return true
		}
	}
	return false
}

// StartDispatchers - run submission and prescan dispatchers
func (a *Application) StartDispatchers() {
	a.submitWg.Add(a.submitJobs)
	for i := 0; i < a.submitJobs; i++ {
		go a.SubmissionDispatcher()
	}
	a.prescanWg.Add(a.prescanJobs)
	for i := 0; i < a.prescanJobs; i++ {
		go a.PrescanDispatcher()
	}
}

// PrescanDispatcher - process all files in prescan channel
func (a *Application) PrescanDispatcher() {
	defer a.prescanWg.Done()
	for file := range a.prescan {
		a.PrescanFile(file)
	}
}

// PrescanFile - preliminary file checks
func (a *Application) PrescanFile(file *File) {
	if a.filter != nil {
		submit, err := a.filter.CheckFile(file)
		if err != nil {
			log.Fatal(err)
		}
		if !submit {
			log.Printf("Ignore: %v", file)
			return
		}
	}
	if file.Info.Size() > int64(a.maxFileSize) {
		if !a.accept["bigFile"] {
			log.Printf("Too big (%d) bytes file: %v", file.Info.Size(), file)
			a.IncReturnCode()
		} else {
			log.Printf("Skip %d bytes file: %v", file.Info.Size(), file)
		}
		return
	}
	a.submit <- file
}

// SubmissionDispatcher - process files in submit channel
func (a *Application) SubmissionDispatcher() {
	defer a.submitWg.Done()
	for file := range a.submit {
		if !a.CheckFile(file) {
			a.IncReturnCode()
		}
	}
}

// CheckFile - check file and return whenever it is Ok
func (a *Application) CheckFile(file *File) bool {
	sha1, err := file.Sha1()
	if err != nil {
		log.Fatal(err)
	}

	sha1List := []string{sha1}
	duplicates, err := a.analyzer.CheckDuplicateSample(context.TODO(), sha1List, 0)
	if err != nil {
		log.Fatal(err)
	}

	if len(duplicates) == 0 || !strings.EqualFold(duplicates[0], sha1) {
		err = a.analyzer.UploadSample(context.TODO(), file.Path, sha1)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Uploaded %v", file)
	} else {
		log.Printf("Already uploaded %v", file)
	}
	return a.WaitForResult(file, sha1)
}

// WaitForResult - wait for result from Analyzer for file defined by sha1.
func (a *Application) WaitForResult(file *File, sha1 string) bool {
	for {
		sha1List := []string{sha1}
		briefReport, err := a.analyzer.GetBriefReport(context.TODO(), sha1List)
		if err != nil {
			log.Fatal(err)
		}
		report := briefReport.Reports[0]
		switch report.SampleStatus {
		case ddan.StatusNotFound:
			log.Fatalf("Not found by Analyzer: %s (%v)", sha1, file)
		case ddan.StatusArrived:
			a.SleepLong()
			continue
		case ddan.StatusProcessing:
			a.SleepShort()
			continue
		case ddan.StatusError, ddan.StatusTimeout:
			log.Printf("%v for %v", report.SampleStatus, file)
			fallthrough
		case ddan.StatusDone:
			if report.RiskLevel < 0 {
				log.Printf("ERROR: %v: %v", report.RiskLevel, file)
			} else {
				log.Printf("%v: %v", report.RiskLevel, file)
			}
			return a.Pass(report, file)
		default:
			log.Fatalf("%s: %v: Unexpected status value: %v", sha1, file, report.SampleStatus)
		}
	}
}

// Pass - return whenever file should be accepted to pass.
func (a *Application) Pass(b ddan.BriefReport, file *File) bool {
	switch b.SampleStatus {
	case ddan.StatusNotFound, ddan.StatusArrived, ddan.StatusProcessing:
		log.Fatal(ddan.NotReadyError(ddan.StatusCodeNames[b.SampleStatus]))
	case ddan.StatusDone:
		return a.PassForRiskLevel(b.RiskLevel)
	case ddan.StatusError:
		return a.accept["error"]
	case ddan.StatusTimeout:
		return a.accept["timeout"]
	}
	return false
}

func (a *Application) PassForRiskLevel(riskLevel ddan.Rating) bool {
	switch riskLevel {
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
		return a.accept["error"]
	}
}

// SleepLong - sleep for long when file is still in the queue.
func (a *Application) SleepLong() {
	a.SleepRandom(a.pullInterval)
}

// SleepShort - sleep for short when file is alredy being processed.
func (a *Application) SleepShort() {
	a.SleepRandom(a.pullInterval / 4)
}

// SleepRandom - sleep for random time between d/2 and d.
func (a *Application) SleepRandom(d time.Duration) {
	duration := rand.Int63n(int64(d) / 2) //nolint
	time.Sleep(time.Duration(duration) + d/2)
}
