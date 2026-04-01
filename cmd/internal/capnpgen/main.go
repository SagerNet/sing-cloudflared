package main

import (
	"fmt"
	"go/build"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// envFile returns the name of the Go environment configuration file.
// Copy from https://github.com/golang/go/blob/c4f2a9788a7be04daf931ac54382fbe2cb754938/src/cmd/go/internal/cfg/cfg.go#L150-L166
func envFile() (string, error) {
	if file := os.Getenv("GOENV"); file != "" {
		if file == "off" {
			return "", fmt.Errorf("GOENV=off")
		}
		return file, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	if dir == "" {
		return "", fmt.Errorf("missing user-config dir")
	}
	return filepath.Join(dir, "go", "env"), nil
}

// GetRuntimeEnv returns the value of runtime environment variable,
// that is set by running following command: `go env -w key=value`.
func GetRuntimeEnv(key string) (string, error) {
	file, err := envFile()
	if err != nil {
		return "", err
	}
	if file == "" {
		return "", fmt.Errorf("missing runtime env file")
	}
	var runtimeEnv string
	data, readErr := os.ReadFile(file)
	if readErr != nil {
		return "", readErr
	}
	envStrings := strings.Split(string(data), "\n")
	for _, envItem := range envStrings {
		envItem = strings.TrimSuffix(envItem, "\r")
		envKeyValue := strings.Split(envItem, "=")
		if strings.EqualFold(strings.TrimSpace(envKeyValue[0]), key) {
			runtimeEnv = strings.TrimSpace(envKeyValue[1])
		}
	}
	return runtimeEnv, nil
}

// GetGOBIN returns GOBIN environment variable as a string. It will NOT be empty.
func GetGOBIN() string {
	GOBIN := os.Getenv("GOBIN")
	if GOBIN == "" {
		var err error
		GOBIN, err = GetRuntimeEnv("GOBIN")
		if err != nil {
			return filepath.Join(build.Default.GOPATH, "bin")
		}
		if GOBIN == "" {
			return filepath.Join(build.Default.GOPATH, "bin")
		}
		return GOBIN
	}
	return GOBIN
}

func main() {
	pwd, err := os.Getwd()
	if err != nil {
		fmt.Println("Can not get current working directory.")
		os.Exit(1)
	}

	goBin := GetGOBIN()
	binPath := os.Getenv("PATH")
	pathSlice := []string{pwd, goBin, binPath}
	binPath = strings.Join(pathSlice, string(os.PathListSeparator))
	os.Setenv("PATH", binPath)

	var capnpFiles []string
	walkErr := filepath.Walk("./", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Println(err)
			return err
		}
		if info.IsDir() {
			return nil
		}
		filename := filepath.Base(path)
		if strings.HasSuffix(filename, ".capnp") && filename != "go.capnp" {
			capnpFiles = append(capnpFiles, path)
		}
		return nil
	})
	if walkErr != nil {
		fmt.Println(walkErr)
		os.Exit(1)
	}

	for _, capnpFile := range capnpFiles {
		directory := filepath.Dir(capnpFile)
		base := filepath.Base(capnpFile)
		cmd := exec.Command("capnp", "compile", "-ogo", base)
		cmd.Dir = filepath.Join(pwd, directory)
		cmd.Env = append(cmd.Env, os.Environ()...)
		output, cmdErr := cmd.CombinedOutput()
		if len(output) > 0 {
			fmt.Println(string(output))
		}
		if cmdErr != nil {
			fmt.Println(cmdErr)
			os.Exit(1)
		}
	}
}
