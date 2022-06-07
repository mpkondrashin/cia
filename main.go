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
	"fmt"
	"log"
	"net/url"
	"os"

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
	app := NewApplication(analyzer)
	app.SetIgnore(viper.GetStringSlice("ignore"))
	app.SetJobs(viper.GetInt("analyzer.jobs"))
	app.SetPause(viper.GetDuration("analyer.pullInterval"))
	app.SetMaxFileSize(viper.GetInt("analyzer.maxFileSize"))

	for _, each := range verdictList {
		app.SetAction(each, viper.GetBool("allow."+each))
	}
	err = app.ProcessFolder(viper.GetString("folder"))
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

	viper.SetDefault("analyzer.maxFileSize", "50000000")
	viper.SetDefault("analyzer.pullIntervalSec", "60")
	viper.SetDefault("analyzer.jobs", "100")
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
		return nil, err
	}

	analyzer := ddan.NewClient(productName, hostname)

	URL, err := url.Parse(viper.GetString("analyzer.url"))
	if err != nil {
		return nil, err
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
