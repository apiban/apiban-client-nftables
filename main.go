/*
apiban-client-nftables - add apiban.org data to a nftables set
License: GPLv3
Copyright (c) 2025,2026 Fred Posner

Example build commands:
env GOOS=linux GOARCH=amd64 go build -o apiban-client-nftables
env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o apiban-client-nftables
env GOOS=linux GOARCH=arm GOARM=7 go build -o apiban-client-nftables-pi

*/

package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/apiban/golib"
	"github.com/apiban/nftlib"
	"github.com/goccy/go-yaml"
)

var (
	configFileLocation string = ""
	logFile            string = "/var/log/apiban-nft-client.log"
	skipVerify         bool   = true
	useCounter         bool   = false
	useYaml            bool   = false
)

// ApibanConfig is the structure for the JSON config file
type ApibanConfig struct {
	Apikey     string `json:"apikey"`
	Lkid       string `json:"lkid"`
	Version    string `json:"version"`
	Flush      string `json:"flush"`
	Dataset    string `json:"dataset"`
	Setname    string `json:"setname"`
	FlushAfter int64  `json:"flushafter"`
	Uptime     int64  `json:"uptime"`
	SourceFile string
}

func init() {
	flag.StringVar(&configFileLocation, "config", configFileLocation, "location of configuration file")
	flag.StringVar(&logFile, "log", logFile, "location of log file or - for stdout")
	flag.BoolVar(&skipVerify, "verify", skipVerify, "set to false to skip verify of tls cert")
	flag.BoolVar(&useCounter, "counter", useCounter, "use counter - default is false (no counter)")
	flag.BoolVar(&useYaml, "yaml", useYaml, "use yaml - default is json")

	if !skipVerify {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
}

func main() {
	flag.Parse()
	nonflagargs := flag.Args()
	defer os.Exit(0)

	// open log
	if logFile != "-" && logFile != "stdout" {
		lf, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Panic(err)
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			runtime.Goexit()
		}
		defer lf.Close()

		log.SetOutput(lf)
	}

	// no log error
	log.Print("** Started APIBAN NFT CLIENT")
	log.Print("** Copyright (C) 2025,2026 Fred Posner / The Palner Group, Inc.")
	log.Print("** License: GPLv3")
	now := time.Now()

	// Open our config file
	apiconfig, err := LoadConfig(now)
	if err != nil {
		log.Fatalln(err)
		runtime.Goexit()
	}

	// Check if nft set exists
	currentSet, err := nftlib.NftListSet(apiconfig.Setname)
	if err != nil {
		log.Println("[x] Cannot verify nftables set:", apiconfig.Setname)
		log.Println("[x] error:", err)
		log.Println("[.] trying to create set")
		err := addSet(*apiconfig)
		if err != nil {
			os.Exit(2)
		}

		currentSet, err = nftlib.NftListSet(apiconfig.Setname)
		if err != nil {
			log.Println("[x]", err.Error())
			log.Println("[x] Still cannot verify nftables set:", apiconfig.Setname)
			os.Exit(2)
		}

		log.Println("[+]", currentSet.Set, "verified")
	}

	log.Println("[.]", apiconfig.Setname, "exists. Currently has", len(currentSet.Elements), "elements.")

	// allow cli of FULL to reset Lkid to 100
	if len(nonflagargs) > 0 {
		if nonflagargs[0] == "FULL" {
			log.Print("[.] CLI of FULL received, resetting Lkid")
			apiconfig.Lkid = "100"
		}
	}

	// check uptime
	upsec, err := nftlib.LinuxUptime()
	if err != nil {
		log.Print("[.] unable to check uptime")
	} else {
		if upsec < apiconfig.Uptime {
			log.Println("[.] uptime of", upsec, "is less than", apiconfig.Uptime, " - resetting Lkid")
			apiconfig.Lkid = "100"
		}
	}

	// check if set elements need to be flushed (greater than 7 days)
	flushtime, _ := strconv.ParseInt(apiconfig.Flush, 10, 64)
	flushdiff := now.Unix() - flushtime
	if flushdiff >= apiconfig.FlushAfter {
		err := nftlib.NftFlushSet(currentSet)
		if err != nil {
			log.Print("[.] flushing nftables set failed. ", err.Error())
			os.Exit(2)
		}

		log.Print("[.] set flushed. resetting Lkid and Flush")
		apiconfig.Lkid = "100"
		apiconfig.Flush = strconv.FormatInt(now.Unix(), 10)
	}

	// get banned ips from APIBAN and add to nftables
	i := 0
	for i < 24 {
		log.Println("Checking banned list with ID:", apiconfig.Lkid, " and settype:", apiconfig.Dataset)

		// Get list of banned ip's from APIBAN.org (up to 24 times)
		res, err := golib.Banned(apiconfig.Apikey, apiconfig.Lkid, apiconfig.Dataset)
		if err != nil {
			log.Fatalln("failed to get banned list:", err)
			continue
		}

		if res.ID == apiconfig.Lkid {
			// nothing blocked since last check
			log.Print("Great news... no new bans to add. Exiting...")
			if err := apiconfig.Update(); err != nil {
				log.Fatalln(err)
			}

			currentSet, _ = nftlib.NftListSet(apiconfig.Setname)
			log.Println("[+]", apiconfig.Setname, "now has", len(currentSet.Elements), "elements.")
			os.Exit(0)
		}

		if len(res.IPs) == 0 {
			log.Print("No IP addresses detected. Exiting.")
			os.Exit(0)
		}

		// add the received IPs to the nftable set
		for _, ip := range res.IPs {
			err := nftlib.NftAddSetElement(currentSet, ip)
			if err != nil {
				log.Println("XX error adding", ip, ":", err.Error())
			} else {
				log.Println("+ added", ip, "to", currentSet.Set)
			}

			apiconfig.Lkid = res.ID
		}

		i++
	}

	currentSet, err = nftlib.NftListSet(apiconfig.Setname)
	if err != nil {
		log.Println("[x] Cannot verify nftables set:", apiconfig.Setname)
		log.Println("[x] error:", err)
		os.Exit(2)
	}

	log.Println("[+]", apiconfig.Setname, "now has", len(currentSet.Elements), "elements.")
	if err := apiconfig.Update(); err != nil {
		log.Fatalln(err)
	}
}

// LoadConfig attempts to load the APIBAN configuration file from various locations
func LoadConfig(now time.Time) (*ApibanConfig, error) {
	var fileLocations []string
	var fileName string
	var altFileName string
	if useYaml {
		fileName = "config.yaml"
		altFileName = "config.json"
	} else {
		fileName = "config.json"
		altFileName = "config.yaml"
	}

	// If we have a user-specified configuration file, use it preferentially
	if configFileLocation != "" {
		fileLocations = append(fileLocations, configFileLocation)
		log.Println("[.] received", configFileLocation, "for config")
	} else {
		// If we can determine the user configuration directory, try there
		configDir, err := os.UserConfigDir()
		if err == nil {
			fileLocations = append(fileLocations, fmt.Sprintf("%s/apiban/config.json", configDir))
		}

		// Add standard static locations
		fileLocations = append(fileLocations,
			"/etc/apiban/"+fileName,
			fileName,
			"/usr/local/bin/apiban/"+fileName,
			"/etc/apiban/"+altFileName,
			altFileName,
			"/usr/local/bin/apiban/"+altFileName,
		)
	}

	for _, loc := range fileLocations {
		f, err := os.Open(loc)
		if err != nil {
			continue
		}

		defer f.Close()
		fileExt := loc[len(loc)-4:]
		cfg := new(ApibanConfig)
		if fileExt == "yaml" {
			if err := yaml.NewDecoder(f).Decode(cfg); err != nil {
				log.Println("-> [x] [LoadConfig] error reading:", loc, err)
				return nil, fmt.Errorf("[LoadConfig] failed to read configuration from %s: %w", loc, err)
			}
		} else {
			if err := json.NewDecoder(f).Decode(cfg); err != nil {
				return nil, fmt.Errorf("failed to read configuration from %s: %w", loc, err)
			}
		}

		// Store the location of the config file so that we can update it later
		if useYaml {
			if fileExt == "json" {
				loc = strings.Replace(loc, ".json", ".yaml", -1)
				log.Println("[LoadConfig] will replace json file with", loc)
			}
		}

		cfg.SourceFile = loc
		cfg.Version = "nft1.2"
		if cfg.Apikey == "" || cfg.Apikey == "MY API KEY" || cfg.Apikey == "MYApikey" {
			log.Println("[.] \"" + cfg.Apikey + "\" is not a valid APIBAN key. Please go to apiban.org and get a valid API key.")
			log.Fatalln("Invalid Apikey. Exiting.")
			runtime.Goexit()
		}

		if len(cfg.Lkid) == 0 {
			log.Print("[.] Resetting Lkid")
			cfg.Lkid = "100"
		}

		// if no Flush, reset it to 100
		if len(cfg.Flush) == 0 {
			log.Print("[.] Resetting Flush")
			flushnow := now.Unix()
			cfg.Flush = strconv.FormatInt(flushnow, 10)
		}

		// if no FlushAfter, use a week
		if cfg.FlushAfter < 1 {
			log.Print("[.] Resetting FlushAfter to 1 week")
			cfg.FlushAfter = 604800
		}

		// if no Uptime, use 5 min
		if cfg.Uptime < 1 {
			log.Print("[.] No Uptime. Use 600")
			cfg.Uptime = 600
		}

		log.Println("[.] using", cfg.SourceFile, "for config")
		return cfg, nil
	}

	return nil, errors.New("failed to locate configuration file")
}

// Update rewrite the configuration file with and updated state (such as the Lkid)
func (cfg *ApibanConfig) Update() error {
	f, err := os.Create(cfg.SourceFile)
	if err != nil {
		return fmt.Errorf("failed to open configuration file for writing: %w", err)
	}
	defer f.Close()

	if useYaml {
		enc := yaml.NewEncoder(f, yaml.Indent(2))
		enc.Encode(cfg)
	} else {
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		enc.Encode(cfg)
	}

	return nil
}

func addSet(cfg ApibanConfig) error {
	log.Println("** Attempting to add set and rules")
	log.Println("[-] finding input chains")
	inputChains, err := nftlib.NftGetInputChains()
	if err != nil {
		log.Println("[x] error finding input chain:", err.Error())
		return errors.New("error finding an input chain")
	}

	log.Println("[.] found", inputChains)
	chainDetails, err := nftlib.NftGetChainDetails(inputChains[0])
	if err != nil {
		log.Println("[x] error finding input chain details:", err.Error())
		return errors.New("error getting input chain details")
	}

	log.Println("[.] creating set", cfg.Setname, "in", chainDetails.Table, chainDetails.Chain)
	if useCounter {
		err = nftlib.NftAddSetCounter(chainDetails, cfg.Setname)
	} else {
		err = nftlib.NftAddSet(chainDetails, cfg.Setname)
	}

	if err != nil {
		log.Println("[x] unable to create set:", err.Error())
		return errors.New("unable to create set")
	}

	log.Println("[.] creating input rule", cfg.Setname, "in", chainDetails.Table, chainDetails.Chain)
	err = nftlib.NftAddSetRuleInput(chainDetails, cfg.Setname)
	if err != nil {
		log.Println("[*] unable to create input rule:", err.Error())
		log.Println("[*] input rule failed. Set created though... continuing.")
		log.Println("[*] *** PLEASE MANUALLY CREATE A RULE FOR THE", cfg.Setname, "SET")
	}

	log.Println("[-] finding output chains")
	outputchains, err := nftlib.NftGetOutputChains()
	if err != nil {
		log.Println("[x] error finding output chain:", err.Error())
		return nil
	}

	log.Println("[.] found", outputchains)
	chainDetails, err = nftlib.NftGetChainDetails(outputchains[0])
	if err != nil {
		log.Println("[x] error finding output chain details:", err.Error())
		return nil
	}

	log.Println("[.] creating output rule", cfg.Setname, "in", chainDetails.Table, chainDetails.Chain)
	err = nftlib.NftAddSetRuleOutput(chainDetails, cfg.Setname)
	if err != nil {
		log.Println("[*] unable to create output rule:", err.Error())
		log.Println("[*] output rule failed. Set created though... continuing.")
		log.Println("[*] *** PLEASE MANUALLY CREATE A RULE FOR THE", cfg.Setname, "SET")
	}

	return nil
}
