package packer

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
)

// Package encapsulates all the logic and functionality for reading
// and writing packages.
type Package struct {
	// Input state
	packagePath string // Filename of existing or intended data package

	// GPG-related things
	keyPath        string // Path to public key file for encrypting or private key file for decrypting
	publicKeyEmail string // Email of public key for lookup on remote keyserver (alternative to keyPath)
	keyPassPath    string // Path to file containing passphrase for the private key

	// Working properties
	outWriteCloser  io.WriteCloser
	encWriteCloser  io.WriteCloser
	gzipWriteCloser *gzip.Writer
	tarWriteCloser  *tar.Writer
	tarReader       *tar.Reader
	gzipReader      *gzip.Reader
	encReader       io.Reader
	inReadCloser    io.ReadCloser
	keyReader       io.ReadCloser
}

// New takes a Config object and returns a properly configured Package
// that is ready to use.
func New(cfg *Config) (*Package, error) {

	var p = new(Package)

	p.packagePath = cfg.PackagePath
	p.keyPath = cfg.KeyPath
	p.publicKeyEmail = cfg.PublicKeyEmail
	p.keyPassPath = cfg.KeyPassPath

	return p, nil
}

// functions or methods shared by pack and unpack

func keyReader(keyPath string) (io.Reader, error) {
	keyReaderFile, err := os.Open(keyPath)
	if err != nil {
		return nil, err
	}

	defer keyReaderFile.Close()

	return io.Reader(keyReaderFile), nil
}

func (p *Package) gpgInUse() bool {
	return p.keyPath != "" || p.publicKeyEmail != ""
	return FileNameHasGPG(p.packagePath)
}
