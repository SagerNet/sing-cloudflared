package main

import (
	"log"

	"github.com/sagernet/sing-cloudflared/internal/cmd"
)

func main() {
	err := cmd.Execute()
	if err != nil {
		log.Fatal(err)
	}
}
