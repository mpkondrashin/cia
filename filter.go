package main

import (
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/danwakefield/fnmatch"
	"github.com/go-yaml/yaml"
)

var (
	ErrUnknownRuleType = errors.New("unknown rule type")
	ErrNoMatch         = errors.New("no match")
)

type Filter struct {
	Rules []Rule `yaml:"rules"`
}

type Rule struct {
	Submit bool   `yaml:"submit"`
	Type   string `yaml:"type"`
	Value  string `yaml:"value"`
}

func LoadFilter(filePath string) (*Filter, error) {
	yamlData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filePath, err)
	}
	var filter Filter
	err = yaml.UnmarshalStrict(yamlData, &filter)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filePath, err)
	}
	return &filter, nil
}

func (r *Rule) ShouldSubmit(file *File) (bool, error) {
	switch r.Type {
	case "path":
		if fnmatch.Match(r.Value, file.Path, 0) {
			return r.Submit, nil
		}
	case "mime":
		mime, err := file.Mime()
		if err != nil {
			return false, err
		}
		if fnmatch.Match(r.Value, mime, 0) {
			return r.Submit, nil
		}
	default:
		return false, fmt.Errorf("%s: %w", r.Type, ErrUnknownRuleType)
	}
	return false, ErrNoMatch
}

func (f *Filter) CheckFile(file *File) (bool, error) {
	for _, r := range f.Rules {
		shouldSubmit, err := r.ShouldSubmit(file)
		if err != nil {
			if errors.Is(err, ErrNoMatch) {
				continue
			}
			return false, err
		}
		return shouldSubmit, nil
	}
	return false, nil
}
