package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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

func (a *Application) SetPause(pullInterval time.Duration) *Application {
	a.pullInterval = pullInterval
	return a
}

func (a *Application) SetAction(actionName string, pass bool) *Application {
	a.accept[actionName] = pass
	return a
}

func (a *Application) SetPrescanJobs(jobs int) *Application {
	a.prescanJobs = jobs
	return a
}

func (a *Application) SetSubmitJobs(jobs int) *Application {
	a.submitJobs = jobs
	return a
}

func (a *Application) SetMaxFileSize(maxFileSize int) *Application {
	a.maxFileSize = maxFileSize
	return a
}

func (a *Application) SetFilter(filter *Filter) *Application {
	a.filter = filter
	return a
}

func (a *Application) SetSkipFolders(skipFolders []string) *Application {
	a.skipFolders = skipFolders
	return a
}

func (a *Application) IncReturnCode() {
	_ = atomic.AddInt32(&a.returnCode, 1)
}

func (a *Application) ProcessFolder(folder string) error {
	startTime := time.Now()
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
	//start := time.Now()
	count := 0
	err = filepath.Walk(folder, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if a.ShouldSkipFolder(path) {
				return filepath.SkipDir
			}
			return nil
		}
		count++
		//	if start.After(time.Now().Add(10 * time.Second)) {
		//		start = time.Now()
		//		log.Printf("Found %d files", count)
		//	}
		file := NewFileWithInfo(path, info)
		a.prescan <- file
		return nil
	})
	if err != nil {
		return err
	}
	log.Printf("Scan complete. Found %d files. Waiting for analysis results", count)
	close(a.prescan)
	a.prescanWg.Wait()
	close(a.submit)
	a.submitWg.Wait()
	duration := time.Since(startTime)
	log.Printf("Operation time: %v", duration)
	if a.returnCode > 0 {
		return fmt.Errorf("Found %d inadmissible files", a.returnCode)
	}
	return nil
}

func (a *Application) ShouldSkipFolder(folder string) bool {
	for _, each := range a.skipFolders {
		if strings.HasPrefix(folder, each) {
			return true
		}
	}
	return false
}

func (a *Application) StartDispatchers() {
	//log.Print("StartSubmissionDispatchers")
	a.submitWg.Add(a.submitJobs)
	for i := 0; i < a.submitJobs; i++ {
		//log.Print("Start submission")
		go a.SubmissionDispatcher()
	}
	//log.Print("StartPrescanDispatchers")
	a.prescanWg.Add(a.prescanJobs)
	for i := 0; i < a.prescanJobs; i++ {
		//log.Print("Start prescan")
		go a.PrescanDispatcher()
	}
}

func (a *Application) PrescanDispatcher() {
	defer a.prescanWg.Done()
	//log.Print("Start PrescanDispatcher")
	for file := range a.prescan {
		a.PrescanFile(file)
	}
}

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

func (a *Application) SubmissionDispatcher() {
	defer a.submitWg.Done()
	for file := range a.submit {
		if !a.CheckFile(file) {
			//	log.Printf("INC %v", file)
			a.IncReturnCode()
		}
	}
}

func (a *Application) CheckFile(file *File) bool {
	//log.Printf("CheckFile %s", path)
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

// WaitForResult - wait for result from Analyzer for file defined by sha1
func (a *Application) WaitForResult(file *File, sha1 string) bool {
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
			log.Fatalf("Not found by Analyzer: %s (%v)", sha1, file)
		case ddan.StatusArrived:
			a.SleepLong()
			continue
		case ddan.StatusProcessing:
			a.SleepShort()
			continue
		case ddan.StatusError:
			fallthrough
		case ddan.StatusTimeout:
			log.Printf("%v for %v", report.SampleStatus, file)
			fallthrough
		case ddan.StatusDone:
			log.Printf("%v: %v", report.RiskLevel, file)
			ok, err := a.Pass(report)
			if err != nil {
				log.Printf("%s: %v: %v", sha1, file, err)
				return false
			}
			return ok
		default:
			log.Fatalf("%s: %v: Unexpected status value: %v", sha1, file, report.SampleStatus)
		}
	}
}

// Pass - return whenever file should be accepted to pass
func (a *Application) Pass(b ddan.BriefReport) (bool, error) {
	switch b.SampleStatus {
	case ddan.StatusNotFound, ddan.StatusArrived, ddan.StatusProcessing:
		log.Fatal(ddan.NotReadyError(ddan.StatusCodeNames[b.SampleStatus]))
	case ddan.StatusDone:
		switch b.RiskLevel {
		case ddan.RatingUnsupported:
			return a.accept["unscannable"], nil
		case ddan.RatingNoRiskFound:
			return true, nil
		case ddan.RatingLowRisk:
			return a.accept["lowRisk"], nil
		case ddan.RatingMediumRisk:
			return a.accept["mediumRisk"], nil
		case ddan.RatingHighRisk:
			return a.accept["highRisk"], nil
		default:
			//log.Fatalf("Unknown RiskLevel: %d", b.RiskLevel)
			return false, fmt.Errorf("Unknown RiskLevel: %v", b)
		}
	case ddan.StatusError:
		return a.accept["error"], nil
	case ddan.StatusTimeout:
		return a.accept["timeout"], nil
	}
	return false, nil
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
