// Provides methods for packing directories into compressed and optionally
// encrypted files as well as unpacking those files into directories.
package datapackage

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"strings"
)

// DataPackage represents a compressed and optionally encrypted file that may
// or may not exist on disk, yet.
//
// PackagePath is the full path to the data package file, which may or may not
// exist, yet. If it is empty, the package will be Packed or Unpacked to
// STDOUT or from STDIN, respectively.
//
// KeyPath is the full path to a file holding an ASCII-armored GPG key
// for encryption or decryption (in which case the file must contain both
// public and private keys).
//
// PublicKeyEmail is the email associated with a public key uploaded to a key
// server and can be used in place of KeyPath for encryption. If both are
// given, KeyPath is used instead.
//
// KeyPassPath is the full path to a file holding the password for the key.
// The password can alternatively be exported to the PACKER_KEYPASS environment
// variable. The environment variable is preferred if both are given.
type DataPackage struct {
	PackagePath    string // Filename of existing or intended data package.
	KeyPath        string // Path to public key file for encrypting or private key file for decrypting
	PublicKeyEmail string // Email of public key for lookup on remote keyserver (alternative to KeyPath)
	KeyPassPath    string // Path to file containing passphrase for the private key

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
	return d.KeyPath != "" || d.PublicKeyEmail != "" || fileNameHasGPG(d.PackagePath)
}

// fileNameHasGPG returns true if filename ends in .gpg (case-insensitive)
func fileNameHasGPG(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), ".gpg")
}
