package packer

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/openpgp"
)

// WriteHeader writes a new file header to the package and prepares to writes
// that new file's data on the next write.
func (p *Package) writeTarHeader(fi os.FileInfo, path string) error {
	var (
		tarHeader *tar.Header
		err       error
	)

	// Create tar.Header from file info, adding the path.
	if tarHeader, err = tar.FileInfoHeader(fi, ""); err != nil {
		return err
	}

	tarHeader.Name = path

	// Call the WriteHeader method, which prepares the already existing
	// writer to receive another file.
	if err = p.tarWriteCloser.WriteHeader(tarHeader); err != nil {
		return err
	}

	return nil
}

// Write writes data to the current entry in the package.
func (p *Package) Write(b []byte) (int, error) {
	return p.tarWriteCloser.Write(b)
}

// FinishPack closes the package, flushing any unwritten data.
func (p *Package) FinishPack() error {
	var err error

	if err = p.tarWriteCloser.Close(); err != nil {
		return err
	}

	if err = p.gzipWriteCloser.Close(); err != nil {
		return err
	}

	if p.encWriteCloser != nil {
		if err = p.encWriteCloser.Close(); err != nil {
			return err
		}
	}

	if err = p.outWriteCloser.Close(); err != nil {
		return err
	}

  if p.keyReader != nil {
    if err = p.keyReader.Close(); err != nil {
      return err
    }
  }

	return nil
}

func (p *Package) encryptionKeyReader() (io.Reader, error) {

	var err error

	if p.keyPath != "" {

		p.keyReader, err = os.Open(p.keyPath)
		if err != nil {
			return nil, fmt.Errorf("encryptionKeyReader: error opening p.keyPath: %v", err)
		}

		return io.Reader(p.keyReader), nil

	} else if p.publicKeyEmail != "" {

		gpgQueryTemplate := "http://pool.sks-keyservers.net:11371/pks/lookup?search={{EMAIL}}&op=get&options=mr"
		email := url.QueryEscape(p.publicKeyEmail)
		gpgQuery := strings.Replace(gpgQueryTemplate, "{{EMAIL}}", email, 1)

		response, err := http.Get(gpgQuery)
		if err != nil {
			return nil, fmt.Errorf("Error fetching public key from pool.sks-keyservers.net:11371: %v", err)
		}
		p.keyReader = response.Body
		return p.keyReader, nil

	} else {
		return nil, errors.New("Either KeyPath or PublicKeyEmail must be specified")
	}
}

// makeFilePackFunc returns a filepath.WalkFunc that packs files in the basePath
// directory using the passed writer.
func (p *Package) makeFilePackFunc(basePath string) filepath.WalkFunc {

	return func(path string, fi os.FileInfo, inErr error) (err error) {

		var (
			relPath string
			r       *os.File
		)

		// Return an error passed by filepath.Walk.
		if err = inErr; err != nil {
			return err
		}

		// Skip directories.
		if fi.IsDir() {
			return nil
		}

		// Error if non-csv file found.
		if filepath.Ext(path) != ".csv" {
			return fmt.Errorf("non-csv file found: %s", path)
		}

		// Get path relative to base of package directory.
		if relPath, err = filepath.Rel(basePath, path); err != nil {
			return err
		}

		// Write file header to writer, preparing for writing of new file.
		if err = p.writeTarHeader(fi, relPath); err != nil {
			return err
		}

		// Open data file.
		if r, err = os.Open(path); err != nil {
			return err
		}

		defer r.Close()

		// Copy data file to writer.
		log.Printf("packer: writing '%s' to package", fi.Name())

		if _, err = io.Copy(p, r); err != nil {
			return err
		}

		return nil
	}

}

// Pack writes the data files at base path into a package.
func (p *Package) Pack(dataDirPath string) error {

	var (
		err          error
		filePackFunc filepath.WalkFunc
	)

	// Open the first level of writer, keeping the API for writing and closing
	// to it consistent regardless of the underlying implementation.
	if p.packagePath != "" {
		if p.outWriteCloser, err = os.OpenFile(p.packagePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644); err != nil {
			return err
		}
	} else {
		p.outWriteCloser = os.Stdout
	}

	// Open the encryption writer if desired
	if p.gpgInUse() {

		keyReader, err := p.encryptionKeyReader()
		if err != nil {
			return err
		}
		if p.encWriteCloser, err = Encrypt(p.outWriteCloser, keyReader); err != nil {
			return err
		}

	}

	if p.encWriteCloser != nil {
		p.gzipWriteCloser = gzip.NewWriter(p.encWriteCloser)
		p.tarWriteCloser = tar.NewWriter(p.gzipWriteCloser)
	} else {
		p.gzipWriteCloser = gzip.NewWriter(p.outWriteCloser)
		p.tarWriteCloser = tar.NewWriter(p.gzipWriteCloser)
	}

	// Make a filepath.WalkFunc to pack files into the package.
	filePackFunc = p.makeFilePackFunc(dataDirPath)

	// Write the files into a package.
	if err := filepath.Walk(dataDirPath, filePackFunc); err != nil {
		return err
	}

	p.FinishPack() // flush and close

	return nil
}

// Encrypt takes a writer to encrypt data onto and a reader containing the
// ASCII-armored public key to encrypt with and returns a WriteCloser to write
// onto and close. It assumes there is only one OpenPGP entity involved.
func Encrypt(plainWriter io.Writer, keyReader io.Reader) (io.WriteCloser, error) {

	var (
		entityList openpgp.EntityList
		err        error
	)

	if entityList, err = openpgp.ReadArmoredKeyRing(keyReader); err != nil {
		return nil, fmt.Errorf("Encrypt: error calling ReadArmoredKeyRing: %v", err)
	}

	return openpgp.Encrypt(plainWriter, entityList, nil, nil, nil)
}
