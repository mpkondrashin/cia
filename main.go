/*


1. Search for files
2. Apply ignore list
3. Check local fast_cache(?)
4. Check local cache(?)
5. Check Analyzer Cache
6. Submit files
7. Get brief report
8. Record in caches
9. Return error code


*/
package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"

	_ "github.com/lib/pq"

	"github.com/mpkondrashin/ddan"
	"github.com/spf13/viper"
)

func main() {
	log.Print("Started")
	err := setupConfig()
	if err != nil {
		log.Fatal(err)
	}

	analyzer, err := setupAnalyzer()
	if err != nil {
		log.Fatal(err)
	}
	app := NewApplication(analyzer)
	app.SetPrescanJobs(viper.GetInt("analyzer.prescanJobs"))
	app.SetSubmitJobs(viper.GetInt("analyzer.submitJobs"))
	app.SetPause(viper.GetDuration("analyzer.pullInterval"))
	app.SetMaxFileSize(viper.GetInt("analyzer.maxFileSize"))

	filterPath := viper.GetString("filter")
	if filterPath != "" {
		filter, err := LoadFilter(filterPath)
		if err != nil {
			log.Fatal(err)
		}
		app.SetFilter(filter)
	}

	for _, each := range VerdictList {
		app.SetAction(each, viper.GetBool("allow."+each))
	}

	skipFolders := viper.GetStringSlice("skip")
	if skipFolders != nil {
		app.SetSkipFolders(skipFolders)
	}

	err = app.Run(viper.GetString("folder"))
	if err != nil {
		log.Fatal(err)
	}
	log.Print("Done")
}

func setupConfig() error {
	viper.SetConfigName("cia")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatal(fmt.Errorf("Fatal error config file: %w \n", err))
	}

	viper.SetEnvPrefix("CIA")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	viper.SetDefault("analyzer.maxFileSize", "50000000")
	viper.SetDefault("analyzer.pullInterval", "60s")
	viper.SetDefault("analyzer.prescanJobs", "16")
	viper.SetDefault("analyzer.submitJobs", "60")
	viper.SetDefault("analyzer.ignoreTLSError", "false")
	viper.SetDefault("analyzer.productName", "cia")
	viper.SetDefault("analyzer.sourceID", "500")
	viper.SetDefault("analyzer.sourceName", "pipline")

	viper.SetDefault("action.highRisk", "false")
	viper.SetDefault("action.mediumRisk", "false")
	viper.SetDefault("action.lowRisk", "false")
	viper.SetDefault("action.error", "false")
	viper.SetDefault("action.unscannable", "true")
	viper.SetDefault("action.timeout", "false")
	viper.SetDefault("action.bigFile", "true")
	return nil
}

func setupAnalyzer() (ddan.ClientInterace, error) {
	productName := viper.GetString("analyzer.productName")
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("setup Analyzer: %w", err)
	}

	var analyzer ddan.ClientInterace
	db, dbURL := setupCacheDatabase()
	if db != nil {
		ddanCache, err := ddan.NewCache(db, dbURL)
		if err != nil {
			panic(err)
		}
		analyzer = ddan.NewCachedClient(productName, hostname, ddanCache)
	} else {
		log.Print("WARNING: cache not configured. CIA will run with dramatically reduced performance")
		analyzer = ddan.NewClient(productName, hostname)
	}
	URL, err := url.Parse(viper.GetString("analyzer.url"))
	if err != nil {
		return nil, fmt.Errorf("setup Analyzer: analyzer.url value: %w", err)
	}

	analyzer.SetAnalyzer(URL,
		viper.GetString("analyzer.APIKey"),
		viper.GetBool("analyzer.IgnoreTLSError"),
	)

	analyzer.SetSource(
		viper.GetString("analyzer.sourceID"),
		viper.GetString("analyzer.sourceName"),
	)

	analyzer.SetUUID(
		viper.GetString("analyzer.clientUUID"),
	)
	return analyzer, nil
}

func setupCacheDatabase() (*sql.DB, string) {
	if viper.Get("cache") == nil {
		return nil, ""
	}
	switch viper.GetString("cache.type") {
	case "":
		log.Fatal("cia.yaml: cache.type is missing")
	case "postgres", "postgresql":
		return setupPostgreSQLCache()
	default:
		log.Fatalf("cia.yaml: cache.type %s is not supported", viper.GetString("cache.type"))
	}
	return nil, ""
}
