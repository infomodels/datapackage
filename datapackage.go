// Provides methods for packing directories into compressed and optionally
// encrypted files as well as unpacking those files into directories.
package datapackage

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"os"
)

// DataPackage represents a compressed and optionally encrypted file that may
// or may not exist on disk, yet.
type DataPackage struct {
	// Input state
	packagePath string // Filename of existing or intended data package.

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

// New takes a Config object and returns a properly configured DataPackage
// that is ready to use.
func New(cfg *Config) (*DataPackage, error) {

	if cfg.PackagePath == "" {
		return nil, errors.New("DataPackage instantiation requires Config.PackagePath")
	}

	var d = new(DataPackage)

	d.packagePath = cfg.PackagePath
	d.keyPath = cfg.KeyPath
	d.publicKeyEmail = cfg.PublicKeyEmail
	d.keyPassPath = cfg.KeyPassPath

	return d, nil
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

func (d *DataPackage) gpgInUse() bool {
	return d.keyPath != "" || d.publicKeyEmail != "" || fileNameHasGPG(d.packagePath)
}
