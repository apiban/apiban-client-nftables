// apiban-client-nftables - add apiban.org data to a nftables set
//
// Copyright (C) 2025 Fred Posner
// Copyright (C) 2025 The Palner Group, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// Example build commands:
// GOOS=linux GOARCH=amd64 go build -o apiban-client-nftables
// GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o apiban-client-nftables
// GOOS=linux GOARCH=arm GOARM=7 go build -o apiban-client-nftables-pi

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
	"time"

	"github.com/apiban/golib"
	"github.com/apiban/nftlib"
)

var (
	configFileLocation string
	logFile            string
	skipVerify         bool
)

// ApibanConfig is the structure for the JSON config file
type ApibanConfig struct {
	APIKEY     string `json:"apikey"`
	LKID       string `json:"lkid"`
	VERSION    string `json:"version"`
	FLUSH      string `json:"flush"`
	DATASET    string `json:"dataset"`
	SETNAME    string `json:"setname"`
	sourceFile string
}

func init() {
	flag.StringVar(&configFileLocation, "config", "", "location of configuration file")
	flag.StringVar(&logFile, "log", "/var/log/apiban-nft-client.log", "location of log file or - for stdout")
	flag.BoolVar(&skipVerify, "verify", true, "set to false to skip verify of tls cert")

	if !skipVerify {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
}

func main() {
	flag.Parse()
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
	log.Print("** Licensed under GPLv2. See LICENSE for details.")
	now := time.Now()

	// Open our config file
	apiconfig, err := LoadConfig(now)
	if err != nil {
		log.Fatalln(err)
		runtime.Goexit()
	}

	// Check if nft set exists
	currentSet, err := nftlib.NftListSet(apiconfig.SETNAME)
	if err != nil {
		log.Println("[x] Cannot verify nftables set:", apiconfig.SETNAME)
		log.Println("[x] error:", err)
		os.Exit(2)
	}

	log.Println("[.]", apiconfig.SETNAME, "exists. Currently has", len(currentSet.Elements), "elements.")

	// allow cli of FULL to reset LKID to 100
	if len(os.Args) > 1 {
		arg1 := os.Args[1]
		if arg1 == "FULL" {
			log.Print("[.] CLI of FULL received, resetting LKID")
			apiconfig.LKID = "100"
		}
	}

	// check if set elements need to be flushed (greater than 7 days)
	flushtime, _ := strconv.ParseInt(apiconfig.FLUSH, 10, 64)
	flushdiff := now.Unix() - flushtime
	if flushdiff >= 604800 {
		err := nftlib.NftFlushSet(currentSet)
		if err != nil {
			log.Print("[.] flushing nftables set failed. ", err.Error())
			os.Exit(2)
		}

		log.Print("[.] set flushed. resetting LKID and FLUSH")
		apiconfig.LKID = "100"
		apiconfig.FLUSH = strconv.FormatInt(now.Unix(), 10)
	}

	// get banned ips from APIBAN and add to nftables
	i := 0
	for i < 24 {
		log.Println("Checking banned list with ID:", apiconfig.LKID, " and settype:", apiconfig.DATASET)

		// Get list of banned ip's from APIBAN.org (up to 24 times)
		res, err := golib.Banned(apiconfig.APIKEY, apiconfig.LKID, apiconfig.DATASET)
		if err != nil {
			log.Fatalln("failed to get banned list:", err)
			continue
		}

		if res.ID == apiconfig.LKID {
			// nothing blocked since last check
			log.Print("Great news... no new bans to add. Exiting...")
			if err := apiconfig.Update(); err != nil {
				log.Fatalln(err)
			}

			currentSet, err = nftlib.NftListSet(apiconfig.SETNAME)
			log.Println("[+]", apiconfig.SETNAME, "now has", len(currentSet.Elements), "elements.")
			os.Exit(0)
		}

		if len(res.IPs) == 0 {
			log.Print("No IP addresses detected. Exiting.")
			os.Exit(0)
		}

		// add the received IPs to ghe nftable set
		for _, ip := range res.IPs {
			err := nftlib.NftAddSetElement(currentSet, ip)
			if err != nil {
				log.Println("XX error adding", ip, ":", err.Error())
			} else {
				log.Println("+ added", ip, "to", currentSet.Set)
			}

			apiconfig.LKID = res.ID
		}

		i++
	}

	currentSet, err = nftlib.NftListSet(apiconfig.SETNAME)
	if err != nil {
		log.Println("[x] Cannot verify nftables set:", apiconfig.SETNAME)
		log.Println("[x] error:", err)
		os.Exit(2)
	}

	log.Println("[+]", apiconfig.SETNAME, "now has", len(currentSet.Elements), "elements.")
}

// LoadConfig attempts to load the APIBAN configuration file from various locations
func LoadConfig(now time.Time) (*ApibanConfig, error) {
	var fileLocations []string

	// If we have a user-specified configuration file, use it preferentially
	if configFileLocation != "" {
		fileLocations = append(fileLocations, configFileLocation)
	}

	// If we can determine the user configuration directory, try there
	configDir, err := os.UserConfigDir()
	if err == nil {
		fileLocations = append(fileLocations, fmt.Sprintf("%s/apiban/config.json", configDir))
	}

	// Add standard static locations
	fileLocations = append(fileLocations,
		"/etc/apiban/config.json",
		"config.json",
		"/usr/local/bin/apiban/config.json",
	)

	for _, loc := range fileLocations {
		f, err := os.Open(loc)
		if err != nil {
			continue
		}

		defer f.Close()
		cfg := new(ApibanConfig)
		if err := json.NewDecoder(f).Decode(cfg); err != nil {
			return nil, fmt.Errorf("failed to read configuration from %s: %w", loc, err)
		}

		// Store the location of the config file so that we can update it later
		cfg.sourceFile = loc
		cfg.VERSION = "nft1.0"
		if cfg.APIKEY == "" || cfg.APIKEY == "MY API KEY" {
			log.Println("[.] \"" + cfg.APIKEY + "\" is not a valid APIBAN key. Please go to apiban.org and get a valid API key.")
			log.Fatalln("Invalid APIKEY. Exiting.")
			runtime.Goexit()
		}

		if len(cfg.LKID) == 0 {
			log.Print("[.] Resetting LKID")
			cfg.LKID = "100"
		}

		// if no FLUSH, reset it to 100
		if len(cfg.FLUSH) == 0 {
			log.Print("[.] Resetting FLUSH")
			flushnow := now.Unix()
			cfg.FLUSH = strconv.FormatInt(flushnow, 10)
		}

		return cfg, nil
	}

	return nil, errors.New("failed to locate configuration file")
}

// Update rewrite the configuration file with and updated state (such as the LKID)
func (cfg *ApibanConfig) Update() error {
	f, err := os.Create(cfg.sourceFile)
	if err != nil {
		return fmt.Errorf("failed to open configuration file for writing: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(cfg)
}
