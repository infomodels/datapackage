package packer

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"log"
	"os"
	"path/filepath"
	"strings"

	"errors"
	"io"
	"io/ioutil"

	"golang.org/x/crypto/openpgp"
)

// PackageReader encapsulates all the logic and functionality for reading
// packages.
type PackageReader struct {
	decompReader *DecompressingReader
	inReadCloser io.ReadCloser
	encReader    io.Reader
	dataDirPath  string
}

// NewPackageReader takes an input file path (it will read from STDIN if this
// is an empty string) and a Config object and returns a properly configured
// PackageReader that is ready to use.
func NewPackageReader(cfg *Config) (*PackageReader, error) {

	var (
		r   = new(PackageReader)
		err error
	)

	r.dataDirPath = cfg.DataDirPath

	if cfg.PackagePath != "" {

		// Open the basic file reader.
		if r.inReadCloser, err = os.Open(cfg.PackagePath); err != nil {
			return nil, err
		}

	} else {

		// Open the basic STDIN reader.
		r.inReadCloser = os.Stdin

	}

	// Add decryption to the reader if necessary.
	if cfg.KeyPath != "" {
		if r.encReader, err = makeDecryptingReader(r.inReadCloser, cfg); err != nil {
			return nil, err
		}
	}

	// Add decompression to the reader.
	if r.encReader != nil {
		if r.decompReader, err = NewDecompressingReader(r.encReader, cfg.Comp, cfg.PackagePath); err != nil {
			return nil, err
		}
	} else {
		if r.decompReader, err = NewDecompressingReader(r.inReadCloser, cfg.Comp, cfg.PackagePath); err != nil {
			return nil, err
		}
	}

	return r, nil
}

// Next advances to the next file in the package, which will be read on the
// next call to PackageReader.Read.
func (r *PackageReader) Next() (*tar.Header, error) {
	return r.decompReader.Next()
}

// Read reads from the current file in the package.
func (r *PackageReader) Read(b []byte) (int, error) {
	return r.decompReader.Read(b)
}

// Close closes the package reader.
func (r *PackageReader) Close() error {
	return r.inReadCloser.Close()
}

// makeDecryptingReader creates a decrypting reader based on the passed reader
// using the passed config and returns an io.ReadCloser to read from and close.
func makeDecryptingReader(reader io.Reader, cfg *Config) (io.Reader, error) {

	var (
		keyReader        *os.File
		passReader       io.Reader
		passFile         *os.File
		decryptingReader io.Reader
		err              error
	)

	if keyReader, err = os.Open(cfg.KeyPath); err != nil {
		return nil, err
	}

	defer keyReader.Close()

	passReader = strings.NewReader("")

	if cfg.KeyPassPath != "" {

		if passFile, err = os.Open(cfg.KeyPassPath); err != nil {
			return nil, err
		}

		defer passFile.Close()

		passReader = io.Reader(passFile)
	}

	if os.Getenv("PACKER_KEYPASS") != "" {
		passReader = strings.NewReader(os.Getenv("PACKER_KEYPASS"))
	}

	if decryptingReader, err = Decrypt(reader, keyReader, passReader); err != nil {
		return nil, err
	}

	return decryptingReader, nil
}

// Unpack writes files from a package reader to the output directory.
func (r *PackageReader) Unpack() error {

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
		if fileHeader, err = r.Next(); err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		if r.dataDirPath == "" {
			if r.dataDirPath, err = os.Getwd(); err != nil {
				return err
			}
		}

		filePath = filepath.Join(r.dataDirPath, fileHeader.Name)
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

		// Write file from the reader.
		log.Printf("packer: unpacking '%s'", filepath.Base(fileHeader.Name))
		if _, err = io.Copy(file, r); err != nil {
			return err
		}
	}
}

// DecompressingReader wraps zip.Reader and tar.Reader in a consistent API.
type DecompressingReader struct {
	tarReader  *tar.Reader
	gzipReader *gzip.Reader
	zip        bool
	zipReader  *zip.Reader
	zipIndex   int
	zipFile    io.ReadCloser
}

// NewDecompressingReader takes a reader with compressed data, a string
// describing the compression method (".tar.gz", ".tar.bz2", or ".zip"), and
// the size of the reader file and returns a reader that decompresses the data.
func NewDecompressingReader(compressedReader io.Reader, comp string, inputPath string) (*DecompressingReader, error) {

	var (
		r   = new(DecompressingReader)
		fi  os.FileInfo
		err error
	)

	switch comp {
	case ".zip":

		// Handle zip decompression specially because the interface is
		// different.
		var (
			readerAt io.ReaderAt
			found    bool
		)

		r.zip = true
		r.zipIndex = -1

		if readerAt, found = compressedReader.(io.ReaderAt); !found {
			return nil, errors.New("failed to assert io.ReaderAt type on reader")
		}

		// Get file info for zip reader creation.
		if fi, err = os.Stat(inputPath); err != nil {
			return nil, err
		}

		// BUG(aaron0browne): The zip reader is unable to decompress zip
		// archives that that use the DEFLATE64 compression method.
		if r.zipReader, err = zip.NewReader(readerAt, fi.Size()); err != nil {
			return nil, err
		}

	case ".tar.bz2":

		var bzip2Reader io.Reader

		bzip2Reader = bzip2.NewReader(compressedReader)
		r.tarReader = tar.NewReader(bzip2Reader)

	case ".tar.gz":

		// Save the gzipReader for closing later.
		if r.gzipReader, err = gzip.NewReader(compressedReader); err != nil {
			return nil, err
		}

		r.tarReader = tar.NewReader(r.gzipReader)
	}

	return r, nil
}

// Next advances to the next entry in the compressed file.
func (r *DecompressingReader) Next() (header *tar.Header, err error) {

	// Handle underlying zip.Reader specially, since it has different behavior.
	if r.zip {

		r.zipIndex++

		if r.zipIndex < len(r.zipReader.File) {

			var file *zip.File

			file = r.zipReader.File[r.zipIndex]

			if r.zipFile, err = file.Open(); err != nil {
				return nil, err
			}

			if header, err = tar.FileInfoHeader(file.FileHeader.FileInfo(), ""); err != nil {
				return nil, err
			}

			header.Name = file.FileHeader.Name

			return header, nil
		}

		return nil, io.EOF
	}

	// The `tar` package panics on Next when there is nothing in the reader.
	// This most often happens when the binary is invoked with no arguments and
	// nothing on STDIN.
	defer func() {
		if r := recover(); r != nil {
			log.Fatalf("packer: panic while attempting to get next file in package; see `%s -h` for usage", os.Args[0])
		}
	}()

	return r.tarReader.Next()
}

// Read reads from the current entry in the compressed file.
func (r *DecompressingReader) Read(buf []byte) (n int, err error) {

	if r.zip {

		if n, err = r.zipFile.Read(buf); err == io.EOF {
			r.zipFile.Close()
		}

		return n, err
	}

	return r.tarReader.Read(buf)
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
