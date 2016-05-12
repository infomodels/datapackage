package packer

import (
	"errors"
	"strings"
)

// Config holds the configuration values for package manipulation. The fields correspond exactly with the command line flags.
type Config struct {
	DataDirPath    string
	KeyPassPath    string
	KeyPath        string
	PackagePath    string
	PublicKeyEmail string
}

var (
	errNoKey = errors.New("no key path or email given for package with 'gpg' extension")
	errNoGpg = errors.New("no 'gpg' extension on package but key path or email given") // Give a pass to an empty packagePath, though
)

// Verify verifies the validity of a configuration.
func (cfg *Config) Verify() error {
	if cfg.FileNameHasGPG() && cfg.PublicKeyEmail == "" && cfg.KeyPath == "" {
		return errNoKey
	} else if (cfg.PublicKeyEmail != "" || cfg.KeyPath != "") && (cfg.PackagePath != "" && cfg.FileNameHasGPG()) {
		return errNoGpg
	}
	return nil
}

// FileNameHasGPG returns true if filename ends in .gpg (case-insensitive)
func FileNameHasGPG(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), ".gpg")
}

// FileNameHasGPG returns true if receiver's PackagePath ends in .gpg (case-insensitive)
func (cfg *Config) FileNameHasGPG() bool {
	return strings.HasSuffix(strings.ToLower(cfg.PackagePath), ".gpg")
}
