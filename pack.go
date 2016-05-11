package packer

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/openpgp"
)

// PackageWriter encapsulates all the logic and functionality for writing
// packages.
type PackageWriter struct {
	compWriter     *CompressingWriter
	outWriteCloser io.WriteCloser
	encWriteCloser io.WriteCloser
	dataDirPath    string
}

// NewPackageWriter takes a Config object and returns a properly configured
// PackageWriter that is ready to use.
func NewPackageWriter(cfg *Config) (*PackageWriter, error) {

	var (
		w   = new(PackageWriter)
		err error
	)

	w.dataDirPath = cfg.DataDirPath

	// Open the first level of writer, keeping the API for writing and closing
	// to it consistent regardless of the underlying implementation.
	if cfg.PackagePath != "" {
		if w.outWriteCloser, err = os.OpenFile(cfg.PackagePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644); err != nil {
			return nil, err
		}
	} else {
		w.outWriteCloser = os.Stdout
	}

	// Open the encryption writer, if zip compression is not requested. Warn if
	// it is.
	if cfg.Comp != ".zip" {

		keyReader := io.Reader(strings.NewReader(pedsnetDCCPublicKey))

		if cfg.KeyPath != "" {

			keyReaderFile, err := os.Open(cfg.KeyPath)
			if err != nil {
				return nil, err
			}

			defer keyReaderFile.Close()

			keyReader = io.Reader(keyReaderFile)
		}

		if w.encWriteCloser, err = Encrypt(w.outWriteCloser, keyReader); err != nil {
			return nil, err
		}

	} else {
		log.Print("packer: encryption not supported with zip compression, creating unencrypted package writer")
	}

	// Open the compression writer, using the encWriter if it has been created.
	switch cfg.Comp {
	case "":
		cfg.Comp = ".tar.gz"
	case ".tar.bzip2", ".tar.bz2":
		// bzip2 package does not implement a writer.
		return nil, errors.New("bzip2 compression not supported")
	case ".tar.gzip":
		cfg.Comp = ".tar.gz"
	}

	if w.encWriteCloser != nil {
		if w.compWriter, err = NewCompressingWriter(w.encWriteCloser, cfg.Comp); err != nil {
			return nil, err
		}
	} else {
		if w.compWriter, err = NewCompressingWriter(w.outWriteCloser, cfg.Comp); err != nil {
			return nil, err
		}
	}

	return w, nil
}

// WriteHeader writes a new file header to the package and prepares to writes
// that new file's data on the next write.
func (w *PackageWriter) WriteHeader(fi os.FileInfo, path string) error {
	return w.compWriter.WriteHeader(fi, path)
}

// Write writes data to the current entry in the package.
func (w *PackageWriter) Write(b []byte) (int, error) {
	return w.compWriter.Write(b)
}

// Close closes the package, flushing any unwritten data.
func (w *PackageWriter) Close() error {
	var err error

	if err = w.outWriteCloser.Close(); err != nil {
		return err
	}

	if w.encWriteCloser != nil {
		if err = w.encWriteCloser.Close(); err != nil {
			return err
		}
	}

	if err = w.compWriter.Close(); err != nil {
		return err
	}

	return nil
}

// makeFilePackFunc returns a filepath.WalkFunc that packs files in the basePath
// directory using the passed writer.
func (w *PackageWriter) makeFilePackFunc() filepath.WalkFunc {

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
		if relPath, err = filepath.Rel(w.dataDirPath, path); err != nil {
			return err
		}

		// Write file header to writer, preparing for writing of new file.
		if err = w.WriteHeader(fi, relPath); err != nil {
			return err
		}

		// Open data file.
		if r, err = os.Open(path); err != nil {
			return err
		}

		defer r.Close()

		// Copy data file to writer.
		log.Printf("packer: writing '%s' to package", fi.Name())

		if _, err = io.Copy(w, r); err != nil {
			return err
		}

		return nil
	}

}

// Pack writes the data files at base path into a package.
func (w *PackageWriter) Pack() error {

	var filePackFunc filepath.WalkFunc

	// Make a filepath.WalkFunc to pack files into the package.
	filePackFunc = w.makeFilePackFunc()

	// Write the files into a package.
	if err := filepath.Walk(w.dataDirPath, filePackFunc); err != nil {
		return err
	}

	return nil
}

// CompressingWriter wraps zip.Writer and tar.Writer in a consistent API.
type CompressingWriter struct {

	// .tar.gz writers
	tarWriter  *tar.Writer
	gzipWriter *gzip.Writer

	// .zip compression fields
	zip       bool
	zipWriter *zip.Writer
	// zipFile is for storing each successive file object that the zipWriter
	// will return for writing each successive file.
	zipFile io.Writer
}

// NewCompressingWriter takes a writer to compress data onto and a string
// describing the compression method (".tar.gz" or ".zip") and returns a writer
// that can be written to and closed.
func NewCompressingWriter(uncompWriter io.Writer, comp string) (*CompressingWriter, error) {

	var w = new(CompressingWriter)

	if comp == ".zip" {
		w.zip = true
		w.zipWriter = zip.NewWriter(uncompWriter)
		return w, nil
	}

	// BUG(aaron0browne): The .tar.gz format compressed packages output by data
	// models packer cannot be read by standard tar and gzip tools.
	// Unfortunately, this is the default compression format and the only one
	// compatible with encryption. These packages can, of course, be unpacked
	// by data models packer.
	if comp == ".tar.gz" {
		w.gzipWriter = gzip.NewWriter(uncompWriter)
		w.tarWriter = tar.NewWriter(w.gzipWriter)
		return w, nil
	}

	return nil, fmt.Errorf("unsupported compression method: %s", comp)
}

// WriteHeader writes a new file header and prepares to accept the file's
// contents.
func (w *CompressingWriter) WriteHeader(fi os.FileInfo, path string) (err error) {

	if w.zip {

		var zipHeader *zip.FileHeader

		// Create zip.Header from file info, adding the path.
		if zipHeader, err = zip.FileInfoHeader(fi); err != nil {
			return err
		}

		zipHeader.Name = path

		// Call the underlying zip.Writer method, which returns a new file
		// object to write the new file to, even though it is really the same
		// archive. Store this "new" file object for later writing.
		if w.zipFile, err = w.zipWriter.CreateHeader(zipHeader); err != nil {
			return err
		}

		return nil
	}

	var tarHeader *tar.Header

	// Create tar.Header from file info, adding the path.
	if tarHeader, err = tar.FileInfoHeader(fi, ""); err != nil {
		return err
	}

	tarHeader.Name = path

	// Call the underlying tar.Writer.WriteHeader method, which prepares the
	// already existing writer to receive another file.
	if err = w.tarWriter.WriteHeader(tarHeader); err != nil {
		return err
	}

	return nil
}

// Write writes data to the current entry in the archive.
func (w *CompressingWriter) Write(b []byte) (n int, err error) {

	if w.zip {
		return w.zipFile.Write(b)
	}

	return w.tarWriter.Write(b)
}

// Close closes the archive, flushing any unwritten data.
func (w *CompressingWriter) Close() (err error) {

	if w.zip {
		return w.zipWriter.Close()
	}

	// Close both tar and gzip writers if using ".tar.gz" compression.
	if err = w.tarWriter.Close(); err != nil {
		return err
	}

	return w.gzipWriter.Close()
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
		return nil, err
	}

	return openpgp.Encrypt(plainWriter, entityList, nil, nil, nil)
}

const pedsnetDCCPublicKey = `
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: SKS 1.1.5
Comment: Hostname: pgp.mit.edu

mQENBFTPy6gBCADO+bU5KritXPn5mh8PiUf2zDoNOVoxnoVsO1q/vLWmY+Dmk0Tf9CB15K7a
YgLRp++lL7fWqwGhCYitd3fi3lbhpDWJlVGoc3+pbYcivLwVHohJ/coP0sRsk8QlRgQZ9l6k
OxIUl1vRdnip3VVo3U+nuBmShcYDp4QY7s5/VMCrqHE6ho6KtunNUebclsUgGMEhoeWypk7Z
wZHPFIYmdK4E/3Ng6zDmIf1sFXeofi//MtNn8+cZLjaHQ0LFyNIgWdU2lOkNO9N5T3TDvhE5
ZXFsjqawrxVzTQZWZjk6FHrbQgavcIPXEr8JHsOoXE14BU3cE1TbOb8GpUVV/tDOUn/bABEB
AAG0UlBFRFNuZXQgRGF0YSBDb29yZGluYXRpbmcgQ2VudGVyIChEYXRhIFZhbGlkYXRpb24g
S2V5KSA8cGVkc25ldGRjY0BlbWFpbC5jaG9wLmVkdT6JATgEEwECACIFAlTPy6gCGwMGCwkI
BwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJEBuu5RTrlyH35M8H/3PK6fC4h5gCXmAlSgqg19/i
4KBo9g4mQJKk4gUGZj0mEcPuq06/ycWTikYn77Hl5uaEXHGZRixPZ5jIv/Tf71DcorYFsStH
LEXPfIVjCbqWz74jKhf9K9/q7iZMNPx9JeVVDmBYZqwxZ4xHLEzlNXOcNywgXrhkc+Q9GnaN
yYOrwEXcIVpe6OYo9//UpKiglRySrxQqlRmO79BLr7sZydPAPfLlJXWOwTsbVR8jk6IM3Ad6
Cquv8KYHy6uCUryLG/rYai/0jtFb8+V93sJ8tJOf8XjoSY8NO7KWalkc4K2Iyc8g2IQ/bMIC
NmxuZz4GIgFRAumIWfz97CRxfiJgE7i5AQ0EVM/LqAEIAOTL0jAh56TyiSuC94qhV5ogwDrl
IuPs+Ck814pQBaV3n5Mo+CgPGRglPS+cc2M1XVJ5VA3NnSblmHmAV/Zw5/mUw/HIarEIs4P2
GwozhIOTRZ4fR1ZfaMhwWJY6hE4qxKqr4W7YsCABC/S0XsxVQRSfgqYzfYo9IwlHkLSRMBdd
3Z/cUWuMhGDe4Tm0T0phH3YF63sJJa9EAI8jcd4a5g1YSIquoACo1OSZM0RfZ5ZJtoYsFvTx
4uVoBqWhxL/w/mpkDHQzQFe2OIQ0vb7djTs3yzovuYwYvlUJFwP5Pv9kEYDA9bhz/KH4mOKl
UUfMVYd51yDlbixWFn39Xt68XYMAEQEAAYkBHwQYAQIACQUCVM/LqAIbDAAKCRAbruUU65ch
91LCCAC+3J7wm8gDkvlFNfDuOrlF6i/dy+x6tybZ6Ty1WJHx7ux6HJCv+fBORYWMQH0JhyXj
4hxSO7TjN416bz8OADTTaCDlh6GQCMpFrsBNakGbP7KMwQkFWhRW+hJvvUCrR7xlwYBYd7xK
2BWsVG8KdEp42NyZG/wKWsr2zaZ2xcY+SWYUxlq0fo/re2aNRMq9hnPDzaIb2TKA1AOfSDqA
9hpgrb5p6s5oJK5Mkrw3LGWSj0Ae0ovby4iU5cFShuo2JWaybw7J87YkhOQCkrTOoVQvOy/Q
iHCYOTfbjF9Gw4ZCa3Y9i+WgyKbGwqYCyLkT9Qf5VTx9qUp9/KbGRM0NGfW5
=LAW9
-----END PGP PUBLIC KEY BLOCK-----
`
