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
	app := NewApplication(analyzer)
	app.SetJobs(viper.GetInt("analyzer.jobs"))
	app.SetPause(viper.GetDuration("analyer.pullInterval"))
	app.SetMaxFileSize(viper.GetInt("analyzer.maxFileSize"))

	filterPath := viper.GetString("filter")
	if filterPath != "" {
		filter, err := LoadFilter(filterPath)
		if err != nil {
			log.Fatal(err)
		}
		app.SetFilter(filter)
	}

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

	/*
		ddanCachePath := "cache.db"
		db, err := sql.Open("sqlite", ddanCachePath)
		if err != nil {
			panic(fmt.Errorf("%s: %w", ddanCachePath, err))
		}
	*/
	db, dbURL := setupCacheDatabase()
	ddanCache, err := ddan.NewCache(db, dbURL)
	if err != nil {
		panic(err)
	}

	analyzer := ddan.NewCachedClient(productName, hostname, ddanCache)

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

func setupCacheDatabase() (*sql.DB, string) {
	switch viper.GetString("cache.type") {
	case "":
		log.Fatal("cia.yaml: cache.type is missing")
	case "postgres":
		fallthrough
	case "postgresql":
		return setupPostgreSQLCache()
	default:
		log.Fatalf("cia.yaml: cache.type %s is not supported", viper.GetString("cache.type"))
	}
	return nil, ""
}

type PostgresURL struct {
	host     string
	port     string
	username string
	password string
	dbname   string
	sslmode  string
}

func NewPostresURL() *PostgresURL {
	viper.SetDefault("cache.port", "5432")
	viper.SetDefault("cache.username", "postgres")
	viper.SetDefault("cache.dbname", "cia")
	viper.SetDefault("cache.sslmode", "disable")
	return &PostgresURL{
		host:     viper.GetString("cache.host"),
		port:     viper.GetString("cache.port"),
		username: viper.GetString("cache.username"),
		password: viper.GetString("cache.password"),
		dbname:   viper.GetString("cache.dbname"),
		sslmode:  viper.GetString("cache.sslmode"),
	}
}

func (p *PostgresURL) NoDatabaseConnect() string {
	return fmt.Sprintf("postgresql://%s@%s:%s?sslmode=%s&password=%s",
		p.username, p.host, p.port, p.sslmode, p.password)
}

func (p *PostgresURL) Connect() string {
	return fmt.Sprintf("postgresql://%s@%s:%s/%s?sslmode=%s&password=%s",
		p.username, p.host, p.port, p.dbname, p.sslmode, p.password)
}

func (p *PostgresURL) String() string {
	return fmt.Sprintf("postgresql://%s:***@%s:%s/%s?sslmode=%s",
		p.username, p.host, p.port, p.dbname, p.sslmode)
}

func setupPostgreSQLCache() (*sql.DB, string) {
	pURL := NewPostresURL()
	createPostgreDatabase(pURL)
	url := pURL.Connect()
	db, err := sql.Open("postgres", url)
	if err != nil {
		log.Fatalf("%v: Open: %v", pURL, err)
	}
	err = db.Ping()
	if err != nil {
		log.Fatalf("%v: %v", pURL, err)
	}
	return db, pURL.String()
}

func createPostgreDatabase(pURL *PostgresURL) {
	url := pURL.NoDatabaseConnect()
	db, err := sql.Open("postgres", url)
	if err != nil {
		log.Fatalf("%s: Open: %v", url, err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Fatalf("%v: Close: %v", pURL, err)
		}
	}()
	_, err = db.Exec("CREATE DATABASE " + pURL.dbname)
	if err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			log.Fatalf("%v: CREATE DATABASE: %v", pURL, err)
		}
	} else {
		log.Printf("Database %s created", pURL.dbname)
	}
}
