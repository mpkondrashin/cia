package main

import (
	"database/sql"
	"fmt"
	"log"
	"strings"

	"github.com/spf13/viper"
)

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
	execStmt := fmt.Sprintf("CREATE DATABASE \"%s\"", pURL.dbname)
	_, err = db.Exec(execStmt)
	if err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			log.Fatalf("%v: CREATE DATABASE: %v", pURL, err)
		}
	} else {
		log.Printf("Database %s created", pURL.dbname)
	}
}
