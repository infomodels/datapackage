package datapackage

import (
	"errors"
	"strings"
)

// Config holds the configuration values for DataPackage instantiation. The
// PackagePath is required and should be the full path to the data package
// file, which may or may not exist, yet. If the DataPackage is only intended
// to Pack, the full path to a file holding an ASCII-armored public key can be
// given in the KeyPath attribute. Alternatively, the email associated with a
// public key uploaded to a key server can be given in the PublicKeyEmail
// attribute. If both are given, KeyPath is preferred. If the DataPackage is
// intended to Unpack as well, then the KeyPath much be used and the file must
// include the private key as well. If the key is password protected, the path
// to a file holding the password can be given in the KeyPassPath attribute or
// the password can be exported to the PACKER_KEYPASS environment variable. The
// environment variable is preferred if both are given.
type Config struct {
	KeyPassPath    string
	KeyPath        string
	PackagePath    string
	PublicKeyEmail string
}

var (
	errNoKey = errors.New("no key path or email given for package with 'gpg' extension")
	errNoGpg = errors.New("no 'gpg' extension on package but key path or email given") // Give a pass to an empty packagePath, though
)

// verify verifies the validity of a configuration.
func (cfg *Config) verify() error {
	if cfg.fileNameHasGPG() && cfg.PublicKeyEmail == "" && cfg.KeyPath == "" {
		return errNoKey
	} else if (cfg.PublicKeyEmail != "" || cfg.KeyPath != "") && (cfg.PackagePath != "" && cfg.fileNameHasGPG()) {
		return errNoGpg
	}
	return nil
}

// fileNameHasGPG returns true if filename ends in .gpg (case-insensitive)
func fileNameHasGPG(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), ".gpg")
}

// fileNameHasGPG returns true if receiver's PackagePath ends in .gpg (case-insensitive)
func (cfg *Config) fileNameHasGPG() bool {
	return strings.HasSuffix(strings.ToLower(cfg.PackagePath), ".gpg")
}
