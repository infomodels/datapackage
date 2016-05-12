package packer

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/openpgp"
)

// Next advances to the next file in the package, which will be read on the
// next call to Package.Read.
func (p *Package) Next() (*tar.Header, error) {
	// The `tar` package panics on Next when there is nothing in the reader.
	// This most often happens when the binary is invoked with no arguments and
	// nothing on STDIN.
	defer func() {
		if r := recover(); r != nil {
			log.Fatalf("packer: panic while attempting to get next file in package; see `%s -h` for usage", os.Args[0])
		}
	}()

	return p.tarReader.Next()
}

// Read reads from the current file in the package.
func (p *Package) Read(b []byte) (int, error) {
	return p.tarReader.Read(b)
}

// FinishUnpack closes the Unpack operation.
func (p *Package) FinishUnpack() error {
	if err := p.inReadCloser.Close(); err != nil {
		return err
	}
  if p.keyReader != nil {
    if err := p.keyReader.Close(); err != nil {
      return err
    }
  }
	return nil
}

// makeDecryptingReader creates a decrypting reader based on the passed reader
// using the passed config and returns an io.ReadCloser to read from and close.
func (p *Package) makeDecryptingReader() (io.Reader, error) {

	var (
		passReader       io.Reader
		passFile         *os.File
		decryptingReader io.Reader
		err              error
	)

	p.keyReader, err = os.Open(p.keyPath)
	if err != nil {
		return nil, err
	}

	passReader = strings.NewReader("")

	if p.keyPassPath != "" {

		if passFile, err = os.Open(p.keyPassPath); err != nil {
			return nil, err
		}

		//defer passFile.Close()

		passReader = io.Reader(passFile)
	}

	// TODO: shouldn't the env variables be resolved by something else and stuffed into the Config object?
	if os.Getenv("PACKER_KEYPASS") != "" {
		passReader = strings.NewReader(os.Getenv("PACKER_KEYPASS"))
	}

	if decryptingReader, err = Decrypt(p.inReadCloser, p.keyReader, passReader); err != nil {
		return nil, err
	}

	return decryptingReader, nil
}

// Unpack writes files from a package reader to the output directory.
func (p *Package) Unpack(dataDirPath string) error {

	var err error

	if p.packagePath != "" {

		// Open the basic file reader.
		if p.inReadCloser, err = os.Open(p.packagePath); err != nil {
			return fmt.Errorf("Error opening package path: %v", err)
		}

	} else {

		// Open the basic STDIN reader.
		p.inReadCloser = os.Stdin

	}

	// Add decryption to the reader if necessary.
	if p.keyPath != "" {

		if p.encReader, err = p.makeDecryptingReader(); err != nil {
			return fmt.Errorf("makeDecryptingReader() failed: %v", err)
		}
	}

	// Add decompression to the reader.
	if p.encReader != nil {
		if p.gzipReader, err = gzip.NewReader(p.encReader); err != nil {
			return err
		}
		p.tarReader = tar.NewReader(p.gzipReader)
	} else {
		if p.gzipReader, err = gzip.NewReader(p.inReadCloser); err != nil {
			return err
		}
		p.tarReader = tar.NewReader(p.gzipReader)
	}

	for {

		var (
			fileHeader *tar.Header
			filePath   string
			fileDir    string
			fileInfo   os.FileInfo
			file       *os.File
			err        error
		)

		// Advance to next file in the reader or exit with success if there are
		// no more.
		if fileHeader, err = p.Next(); err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		if dataDirPath == "" {
			if dataDirPath, err = os.Getwd(); err != nil {
				return err
			}
		}

		filePath = filepath.Join(dataDirPath, fileHeader.Name)
		fileDir = filepath.Dir(filePath)
		fileInfo = fileHeader.FileInfo()

		// Make directories in file path.
		if err = os.MkdirAll(fileDir, 0766); err != nil {
			return err
		}

		// Open file for writing.
		if file, err = os.OpenFile(filePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, fileInfo.Mode()); err != nil {
			return err
		}
		defer file.Close()

		// Write file from the package reader.
		log.Printf("packer: unpacking '%s'", filepath.Base(fileHeader.Name))
		if _, err = io.Copy(file, p); err != nil {
			return err
		}
	}

	if err = p.FinishUnpack(); err != nil {
		return err
	}
	return nil
}

// Decrypt takes a reader with encrypted data, a reader with the private key,
// and a reader with the passphrase (or an empty string if the key is
// unprotected) and returns an io.ReadCloser that decrypts the data. It assumes
// there is only one OpenPGP entity involved.
func Decrypt(encReader io.Reader, keyReader io.Reader, passReader io.Reader) (io.Reader, error) {

	var (
		entityList openpgp.EntityList
		entity     *openpgp.Entity
		passphrase []byte
		msgDetails *openpgp.MessageDetails
		err        error
	)

	// Read armored private key into entityList.
	if entityList, err = openpgp.ReadArmoredKeyRing(keyReader); err != nil {
		return nil, err
	}

	entity = entityList[0]

	// Decode entity private key and subkey private keys. This assumes there is
	// only one entity involved.
	if passphrase, err = ioutil.ReadAll(passReader); err != nil {
		return nil, err
	}

	passphrase = bytes.TrimSpace(passphrase)

	if entity.PrivateKey != nil && entity.PrivateKey.Encrypted {
		if err = entity.PrivateKey.Decrypt(passphrase); err != nil {
			return nil, err
		}
	}

	for _, subkey := range entity.Subkeys {
		if subkey.PrivateKey != nil && subkey.PrivateKey.Encrypted {
			if err = subkey.PrivateKey.Decrypt(passphrase); err != nil {
				return nil, err
			}
		}
	}

	// Create decrypted message reader.
	if msgDetails, err = openpgp.ReadMessage(encReader, entityList, nil, nil); err != nil {
		return nil, err
	}

	return msgDetails.UnverifiedBody, nil
}
