package main

import (
	"log"

	tool "github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/tools/loadgen"
)

func main() {
	if err := tool.NewRootCommand().Execute(); err != nil {
		log.Fatal(err)
	}
}
