package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

type request struct {
	ID      string              `json:"id"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
	BodyB64 string              `json:"body_b64"`
}

type response struct {
	ID           string   `json:"id"`
	Technologies []string `json:"technologies"`
	Error        string   `json:"error,omitempty"`
}

func main() {
	fingerprintsPath := flag.String("fingerprints", "", "Optional path to fingerprints_data.json to supersede embedded data")
	flag.Parse()

	var (
		client *wappalyzer.Wappalyze
		err    error
	)

	if fingerprintsPath != nil && *fingerprintsPath != "" {
		client, err = wappalyzer.NewFromFile(*fingerprintsPath, true, true)
	} else {
		client, err = wappalyzer.New()
	}
	if err != nil {
		log.Fatalf("failed to initialize wappalyzer: %v", err)
	}

	scanner := bufio.NewScanner(os.Stdin)
	// allow large bodies (default Scanner buffer is 64K)
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 50*1024*1024) // up to ~50MB per line

	encoder := json.NewEncoder(os.Stdout)

	for scanner.Scan() {
		line := scanner.Bytes()
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			_ = encoder.Encode(response{ID: req.ID, Error: fmt.Sprintf("invalid json: %v", err)})
			continue
		}

		body := []byte(req.Body)
		if req.BodyB64 != "" {
			if decoded, err := base64.StdEncoding.DecodeString(req.BodyB64); err == nil {
				body = decoded
			}
		}

		if req.Headers == nil {
			req.Headers = map[string][]string{}
		}

		techs := client.Fingerprint(req.Headers, body)
		out := response{ID: req.ID, Technologies: make([]string, 0, len(techs))}
		for tech := range techs {
			out.Technologies = append(out.Technologies, tech)
		}

		if err := encoder.Encode(out); err != nil {
			log.Printf("failed to encode response: %v", err)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("scanner error: %v", err)
	}
}
