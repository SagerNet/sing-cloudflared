package main

import (
	"bytes"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"os"
)

const sourceURL = "https://raw.githubusercontent.com/cloudflare/cloudflared/refs/heads/master/tlsconfig/cloudflare_ca.go"

func main() {
	response, err := http.Get(sourceURL)
	if err != nil {
		log.Fatal(err)
	}
	defer response.Body.Close()
	content, err := io.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}

	startIndex := bytes.IndexByte(content, '`')
	endIndex := bytes.LastIndexByte(content, '`')
	if startIndex < 0 || endIndex <= startIndex {
		log.Fatal("failed to extract certificate data from source")
	}
	pemData := content[startIndex+1 : endIndex]

	var output []byte
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		output = append(output, pem.EncodeToMemory(block)...)
	}
	if len(output) == 0 {
		log.Fatal("no certificates found")
	}

	err = os.WriteFile("cloudflare_ca.pem", output, 0o644)
	if err != nil {
		log.Fatal(err)
	}
}
