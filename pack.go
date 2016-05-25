package datapackage

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

// writeTarHeader writes a new file header to the package and prepares to write
// that new file's data on the next write.
func (d *DataPackage) writeTarHeader(fi os.FileInfo, path string) error {
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
	if err = d.tarWriteCloser.WriteHeader(tarHeader); err != nil {
		return err
	}

	return nil
}

// write writes data to the current entry in the package.
func (d *DataPackage) write(b []byte) (int, error) {
	return d.tarWriteCloser.Write(b)
}

// finishPack closes the package, flushing any unwritten data.
func (d *DataPackage) finishPack() error {
	var err error

	if err = d.tarWriteCloser.Close(); err != nil {
		return err
	}

	if err = d.gzipWriteCloser.Close(); err != nil {
		return err
	}

	if d.encWriteCloser != nil {
		if err = d.encWriteCloser.Close(); err != nil {
			return err
		}
	}

	if err = d.outWriteCloser.Close(); err != nil {
		return err
	}

	if d.keyReader != nil {
		if err = d.keyReader.Close(); err != nil {
			return err
		}
	}

	return nil
}

func (d *DataPackage) encryptionKeyReader() (io.Reader, error) {

	var err error

	if d.KeyPath != "" {

		d.keyReader, err = os.Open(d.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("encryptionKeyReader: error opening d.keyPath: %v", err)
		}

		return io.Reader(d.keyReader), nil

	} else if d.PublicKeyEmail != "" {

		gpgQueryTemplate := "http://pool.sks-keyservers.net:11371/pks/lookup?search={{EMAIL}}&op=get&options=mr"
		email := url.QueryEscape(d.PublicKeyEmail)
		gpgQuery := strings.Replace(gpgQueryTemplate, "{{EMAIL}}", email, 1)

		response, err := http.Get(gpgQuery)
		if err != nil {
			return nil, fmt.Errorf("Error fetching public key from pool.sks-keyservers.net:11371: %v", err)
		}
		d.keyReader = response.Body
		return d.keyReader, nil

	} else {
		return nil, errors.New("Either KeyPath or PublicKeyEmail must be specified")
	}
}

// makeFilePackFunc returns a filepath.WalkFunc that packs files in the basePath
// directory using the passed writer.
func (d *DataPackage) makeFilePackFunc(basePath string) filepath.WalkFunc {

	return func(path string, fi os.FileInfo, inErr error) error {

		var (
			relPath string
			r       *os.File
			buf     []byte
			err     error
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
		if err = d.writeTarHeader(fi, relPath); err != nil {
			return err
		}

		// Open data file.
		if r, err = os.Open(path); err != nil {
			return err
		}

		defer r.Close()

		// Copy data file to writer.
		log.Printf("writing '%s' to data package", fi.Name())

		buf = make([]byte, 32*1024)

		for {
			nr, er := r.Read(buf)
			if nr > 0 {
				nw, ew := d.write(buf[0:nr])
				if ew != nil {
					err = ew
					break
				}
				if nr != nw {
					err = errors.New("short write")
					break
				}
			}
			if er == io.EOF {
				break
			}
			if er != nil {
				err = er
				break
			}
		}

		return err

	}

}

// Pack writes the data files at base path into a package.
func (d *DataPackage) Pack(dataDirPath string) error {

	var (
		err          error
		filePackFunc filepath.WalkFunc
	)

	// Open the first level of writer, keeping the API for writing and closing
	// to it consistent regardless of the underlying implementation.
	if d.PackagePath != "" {
		if d.outWriteCloser, err = os.OpenFile(d.PackagePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644); err != nil {
			return err
		}
	} else {
		d.outWriteCloser = os.Stdout
	}

	// Open the encryption writer if desired
	if d.gpgInUse() {

		keyReader, err := d.encryptionKeyReader()
		if err != nil {
			return err
		}
		if d.encWriteCloser, err = encrypt(d.outWriteCloser, keyReader); err != nil {
			return err
		}

	}

	// BUG(aaron0browne): The .tar.gz format compressed packages output by
	// DataPackage.Pack cannot be read by standard tar and gzip tools. The
	// authors believe this is due to the underlying library implementations.
	if d.encWriteCloser != nil {
		d.gzipWriteCloser = gzip.NewWriter(d.encWriteCloser)
		d.tarWriteCloser = tar.NewWriter(d.gzipWriteCloser)
	} else {
		d.gzipWriteCloser = gzip.NewWriter(d.outWriteCloser)
		d.tarWriteCloser = tar.NewWriter(d.gzipWriteCloser)
	}

	// Make a filepath.WalkFunc to pack files into the package.
	filePackFunc = d.makeFilePackFunc(dataDirPath)

	// Write the files into a package.
	if err := filepath.Walk(dataDirPath, filePackFunc); err != nil {
		return err
	}

	d.finishPack() // flush and close

	return nil
}

// encrypt takes a writer to encrypt data onto and a reader containing the
// ASCII-armored public key to encrypt with and returns a WriteCloser to write
// onto and close. It assumes there is only one OpenPGP entity involved.
func encrypt(plainWriter io.Writer, keyReader io.Reader) (io.WriteCloser, error) {

	var (
		entityList openpgp.EntityList
		err        error
	)

	if entityList, err = openpgp.ReadArmoredKeyRing(keyReader); err != nil {
		return nil, fmt.Errorf("Encrypt: error calling ReadArmoredKeyRing: %v", err)
	}

	return openpgp.Encrypt(plainWriter, entityList, nil, nil, nil)
}
