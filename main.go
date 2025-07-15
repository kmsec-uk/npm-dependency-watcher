package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	cron "github.com/pardnchiu/go-cron"
)

type Config struct {
	ApiKey      string `json:"apikey"`
	IntervalHrs string `json:"interval"`
	Target      string `json:"target"`
	Client      *http.Client
}

type Package struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Maintainers []string `json:"maintainers"`

	Publisher Publisher `json:"publisher"`
	Date      Date      `json:"date"`
	Version   string    `json:"version"`
}

func (p *Package) IsScoped() bool {
	return strings.HasPrefix(p.Name, "@")
}

type Publisher struct {
	Name    string                 `json:"name"`
	Avatars map[string]interface{} `json:"avatars"`
}

type Date struct {
	TS  int64  `json:"ts"`
	Rel string `json:"rel"`
}

type Data struct {
	Title      string    `json:"title"`
	Dependency string    `json:"dependency"`
	Packages   []Package `json:"packages"`
}

func (c *Config) sendToScanner(packageName string) error {
	req, err := http.NewRequest("GET", "https://dprk-research.kmsec.uk/api/scanner/analyse/package/"+packageName, nil)
	if err != nil {
		return fmt.Errorf("creating request for dependency %s: %w", packageName, err)
	}
	req.Header.Add("accept", "application/json")
	req.Header.Add("authorization", c.ApiKey)
	res, err := c.Client.Do(req)
	if err != nil {
		return fmt.Errorf("sending to scanner: %s: %w", packageName, err)
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code %d from %s", res.StatusCode, res.Request.URL)
	}

	if res.Request.URL.Path == "/login" {
		return fmt.Errorf("api key is incorrect. bot was redirected to /login")
	}
	log.Printf("sent to scanner: %s", packageName)
	return nil
}

func (c *Config) triageDependencies(cutoff int64) error {
	log.Printf("getting dependencies for %s", c.Target)
	req, err := http.NewRequest("GET", "https://www.npmjs.com/browse/depended/"+c.Target, nil)
	if err != nil {
		return fmt.Errorf("creating request for dependency %s: %w", c.Target, err)
	}
	req.Header.Add("accept", "application/json")
	req.Header.Add("x-spiferack", "1")
	req.Header.Add("user-agent", "dprk-hunter (dependencies)")
	res, err := c.Client.Do(req)
	if err != nil {
		return fmt.Errorf("doing request for %s: %w", req.URL, err)
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code %d from %s", res.StatusCode, res.Request.URL)
	}
	var d Data
	err = json.NewDecoder(res.Body).Decode(&d)
	if err != nil {
		return fmt.Errorf("decoding response from %s: %w", res.Request.URL, err)
	}
	if d.Dependency != c.Target {
		return fmt.Errorf("wanted dependency for %s, got %s", c.Target, d.Dependency)
	}
	if len(d.Packages) == 0 {
		return fmt.Errorf("returned 0 dependencies for %s", c.Target)
	}
	triaged := 0
	for _, p := range d.Packages {
		if p.Date.TS < cutoff {
			break
		}
		if p.IsScoped() {
			continue
		}
		err = c.sendToScanner(p.Name)
		if err != nil {
			return err
		}
		triaged++

	}
	return nil
}

func LoadConfig() (*Config, error) {
	var configPath = ".config"

	if isDocker := os.Getenv("DOCKER"); isDocker != "" {
		configPath = "/var/run/secrets/.config"
	}
	b, err := os.ReadFile(configPath)

	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	var config Config
	err = json.Unmarshal(b, &config)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}
	if config.ApiKey == "" {
		return nil, errors.New("apikey not set")
	}
	if config.IntervalHrs == "" {
		return nil, errors.New("interval not set")
	}
	if config.Target == "" {
		return nil, errors.New("target not set")
	}
	return &config, nil
}
func main() {
	quitChannel := make(chan os.Signal, 1)
	signal.Notify(quitChannel, syscall.SIGINT, syscall.SIGTERM)

	// initialise config
	config, err := LoadConfig()
	if err != nil {
		log.Fatal(err)
	}
	config.Client = &http.Client{
		Timeout: 5 * time.Second,
	}
	log.Printf("initialised with dependency target `%s`", config.Target)
	interval, err := strconv.ParseInt(config.IntervalHrs, 10, 64)
	if err != nil {
		log.Fatal(err)
	}

	// Initialize (optional configuration)
	scheduler, err := cron.New(cron.Config{
		Location: time.UTC,
	})

	if err != nil {
		log.Fatal(err)
	}

	// Start scheduler
	scheduler.Start()

	// Add tasks
	_, err = scheduler.Add(fmt.Sprintf("52 */%s * * *", config.IntervalHrs), func() {
		now := time.Now().UnixMilli()
		cutoff := now - time.Hour.Milliseconds()*interval
		as_time := time.UnixMilli(cutoff).UTC()
		log.Printf("now: %d cutoff: %s", now, as_time)
		err := config.triageDependencies(cutoff)
		if err != nil {
			log.Fatal(err)
		}
	}, "hunt for dependencies")

	if err != nil {
		log.Fatal(err)
	}
	// View task list
	// tasks := scheduler.List()
	// fmt.Printf("Currently have %d tasks\n", len(tasks))

	// // Remove specific task
	// scheduler.Remove(id1)

	// // Remove all tasks
	// scheduler.RemoveAll()
	<-quitChannel

	// Graceful shutdown
	ctx := scheduler.Stop()
	<-ctx.Done()
}
