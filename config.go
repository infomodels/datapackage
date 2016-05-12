package packer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Config holds the configuration values for package compression and/or decompression. The fields correspond exactly with the command line flags.
type Config struct {
	Comp        string
	DataDirPath string
	KeyPassPath string
	KeyPath     string
	PackagePath string
	packing     string
}

type pkgExtensions struct {
	gpg bool
	tar bool
	bz2 bool
	gz  bool
	zip bool
}

var (
	errExtConflict = errors.New("compression file extensions conflict with each other")
	errNoTar       = errors.New("cannot use 'bz2' or 'gz' compression without 'tar'")
	errCfgConflict = errors.New("file extensions conflict with passed compression method")
	errNoComp      = errors.New("no compression extensions found")
	errNoKey       = errors.New("no key given for package with 'gpg' extension")
	errNoGpg       = errors.New("no 'gpg' extension on package but key given")
)

// Verify verifies the validity of a configuration.
func (cfg *Config) Verify() error {

	if cfg.PackagePath != "" {
		return cfg.handleExtensions()
	}

	return nil
}

// handleExtensions resolves the package path with the Config object.
// It sets the Comp and Encrypted attributes of the Config object based on the
// file path extensions, or errors if they conflict with pre-existing values.
func (cfg *Config) handleExtensions() error {

	var (
		name string
		exts = new(pkgExtensions)
		j    int
		i    int
	)

	name = filepath.Base(cfg.PackagePath)

	// Read file extensions and normalize them into a struct.
	j = len(name)

	for i = len(name) - 1; i >= 0; i-- {

		if name[i] == '.' {

			switch name[i+1 : j] {

			case "gpg":
				exts.gpg = true
				j = i

			case "tar":
				exts.tar = true
				j = i

			case "bzip2", "bz2":
				exts.bz2 = true
				j = i

			case "gzip", "gz":
				exts.gz = true
				j = i

			case "zip":
				exts.zip = true
				j = i

			default:
				return fmt.Errorf("unexpected file extension: %s\n", name[i+1:j])
			}
		}
	}

	// Resolve config with file extensions, throwing errors where appropriate.
	switch {

	case exts.gz && exts.bz2 || exts.gz && exts.zip || exts.bz2 && exts.zip:
		return errExtConflict

	case exts.gz && !exts.tar || exts.bz2 && !exts.tar:
		return errNoTar

	case exts.tar && exts.gz:
		if cfg.Comp != "" && cfg.Comp != ".tar.gz" && cfg.Comp != ".tar.gzip" {
			return errCfgConflict
		}
		cfg.Comp = ".tar.gz"

	case exts.tar && exts.bz2:
		if cfg.Comp != "" && cfg.Comp != ".tar.bz2" && cfg.Comp != ".tar.bzip2" {
			return errCfgConflict
		}
		cfg.Comp = ".tar.bz2"

	case exts.zip:
		if cfg.Comp != "" && cfg.Comp != ".zip" {
			return errCfgConflict
		}
		cfg.Comp = ".zip"

	default:
		return errNoComp
	}

	switch {

	case cfg.KeyPath == "" && exts.gpg:
		return errNoKey

	case cfg.KeyPath != "" && !exts.gpg:
		return errNoGpg

	}

	return nil
}

// IsDir returns whether or not the passed path is a directory.
func IsDir(path string) (bool, error) {

	var (
		fi  os.FileInfo
		err error
	)

	// Stat input path to get file info.
	if fi, err = os.Stat(path); err != nil {
		return false, err
	}

	return fi.IsDir(), nil
}
