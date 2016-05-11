package packer

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/chop-dbhi/data-models-service/client"
)

const dataModelsService = "http://data-models.origins.link"

// Default *ordered* header.
var canonicalHeader = []string{
	"organization",
	"filename",
	"checksum",
	"cdm",
	"cdm-version",
	"table",
	"etl",
	"data-version",
}

// Permitted metadata header values and whether or not they are required.
var headerReq = map[string]bool{
	"organization": true,
	"filename":     true,
	"checksum":     true,
	"cdm":          true,
	"cdm-version":  false,
	"table":        true,
	"etl":          true,
	"data-version": false,
}

// CreateOrVerifyMetadataFile is a convenience function that takes a data
// directory path and a set of metadata information and creates a metadata file
// if none exists or verifies one that already does.
func CreateOrVerifyMetadataFile(cfg *Config, verifyOnly bool) error {

	var (
		metadata     *Metadata
		metadataPath string
		metadataFile *os.File
		err          error
	)

	//

	// Create a Metadata object for this directory.
	if metadata, err = NewMetadata(cfg); err != nil {
		return err
	}

	// Attempt to open the metadata file for writing and examine file opening
	// error to determine if we need to make the metadata file or just verify
	// it.
	metadataPath = filepath.Join(cfg.DataDirPath, "metadata.csv")
	metadataFile, err = os.OpenFile(metadataPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)

	// File opened for writing without error, create it.
	if err == nil {

		defer metadataFile.Close()

		if verifyOnly {
			return errors.New("metadata file not found")
		}

		if err = metadata.Make(metadataFile); err != nil {
			return err
		}

		return nil
	}

	// File already exists, verify it.
	if os.IsExist(err) {

		if metadataFile, err = os.Open(metadataPath); err != nil {
			return err
		}

		defer metadataFile.Close()

		if err = metadata.Check(metadataFile); err != nil {
			return err
		}

		return nil
	}

	// Report any other error.
	return err
}

// Metadata represents a set of metadata for a particular data archive
// directory.
type Metadata struct {
	header       []string
	recordMaps   []map[string]string
	path         string
	site         string
	model        string
	modelVersion string
	dataVersion  string
	etl          string
	service      string
	/* serviceModels is a simplified version of data models service information
	   and should look like:
	   {
	       "pedsnet": {
	   	    "sorted": ["1.0.0", "2.0.0", "2.1.0"],
	   		"1.0.0": ["table1", "table2", ...],
	   		...
	   	},
	   	...
	   }
	*/
	serviceModels map[string]map[string]sort.StringSlice
}

// NewMetadata creates a new Metadata object when given a populated config.
func NewMetadata(cfg *Config) (*Metadata, error) {

	var (
		c       *client.Client
		cModels *client.Models
		mFound  bool
		vFound  bool
		m       *Metadata
		err     error
	)

	// Return error if path not given.
	if cfg.DataDirPath == "" {
		return nil, errors.New("the Metadata object requires cfg.DataDirPath")
	}

	// Initialize with any passed metadata information, standardizing to
	// lowercase where appropriate.
	m = &Metadata{
		path:          cfg.DataDirPath,
		site:          cfg.Site,
		model:         strings.ToLower(cfg.Model),
		modelVersion:  strings.ToLower(cfg.ModelVersion),
		dataVersion:   strings.ToLower(cfg.DataVersion),
		etl:           cfg.Etl,
		service:       cfg.Service,
		serviceModels: make(map[string]map[string]sort.StringSlice),
	}

	// Initialize data models service client.
	if m.service == "" {
		m.service = dataModelsService
	}

	if c, err = client.New(m.service); err != nil {
		return nil, err
	}

	if err = c.Ping(); err != nil {
		return nil, err
	}

	// Construct serviceModels map.
	if cModels, err = c.Models(); err != nil {
		return nil, err
	}

	for _, cModel := range cModels.List() {

		// Initialize map for each model.
		if m.serviceModels[cModel.Name] == nil {
			m.serviceModels[cModel.Name] = make(map[string]sort.StringSlice)
		}

		m.serviceModels[cModel.Name]["sorted"] = append(m.serviceModels[cModel.Name]["sorted"], cModel.Version)
		m.serviceModels[cModel.Name][cModel.Version] = cModel.Tables.Names()
	}

	// Check that model and model version, if passed, exist in models retrieved
	// from service.
	if m.model != "" {

		for model, versionInfo := range m.serviceModels {

			versions := versionInfo["sorted"]

			// Sort while we're searching.
			versions.Sort()

			if m.model == model {

				mFound = true

				// Default to the latest model version.
				if m.modelVersion == "" {
					m.modelVersion = versions[len(versions)-1]
					vFound = true
					break
				}

				for _, version := range versions {
					if m.modelVersion == version {
						vFound = true
						break
					}
				}

				break
			}
		}

		if !mFound || !vFound {
			return nil, fmt.Errorf("model '%s' version '%s' not found in data models service", m.model, m.modelVersion)
		}
	}

	return m, nil
}

// readData transforms metadata (csv-format) data from a reader into the proper
// attributes on the Metadata object.
func (m *Metadata) readData(r io.Reader) (err error) {

	var (
		csvReader *csv.Reader
		line      int
	)

	// Create a strict csv.Reader
	csvReader = csv.NewReader(r)
	csvReader.LazyQuotes = false
	csvReader.TrimLeadingSpace = false

	// Read in the header, standardizing to lowercase and ensuring no
	// unexpected values are present.
	if m.header, err = csvReader.Read(); err != nil {
		return err
	}

	for i, headerVal := range m.header {

		m.header[i] = strings.ToLower(headerVal)
		found := false

		for _, cHeaderVal := range canonicalHeader {
			if m.header[i] == cHeaderVal {
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("unexpected header value: %s", headerVal)
		}
	}

	line++

	// Ensure required header values are present.
	for cHeaderVal, req := range headerReq {

		if req {

			found := false

			for _, headerVal := range m.header {
				if headerVal == cHeaderVal {
					found = true
					break
				}
			}

			if !found {
				return fmt.Errorf("missing required header value: %s", cHeaderVal)
			}
		}
	}

	// Read records into the Metadata record maps.
	for {

		// Get next record, exiting if there's no more.
		record, err := csvReader.Read()

		if err == io.EOF {
			break
		}

		if err != nil {
			return err
		}

		line++

		// Create map of header values to record values.
		recordMap := make(map[string]string)
		m.recordMaps = append(m.recordMaps, recordMap)

		for i, val := range record {
			if m.header[i] == "organization" || m.header[i] == "filename" || m.header[i] == "etl" {
				recordMap[m.header[i]] = val
			} else {
				recordMap[m.header[i]] = strings.ToLower(val)
			}
		}

		recordMap["line"] = string(line)
	}

	return nil
}

// Check checks the validity of metadata (csv-format) records in the passed
// reader. Specifically, they are checked against any existing information on
// the Metadata object and then against information from the data models
// service. If all of those checks pass, then each checksum is checked for
// accuracy.
func (m *Metadata) Check(r io.Reader) (err error) {

	// Read data into Metadata in a usable format.
	if err = m.readData(r); err != nil {
		return err
	}

	// Validate records values, except for checksums.
	for _, recordMap := range m.recordMaps {

		var (
			mFound bool
			vFound bool
			tFound bool
		)

		// Check that required values are present.
		for cHeaderVal, req := range headerReq {
			if req && recordMap[cHeaderVal] == "" {
				return fmt.Errorf("line '%s' missing required value '%s'", recordMap["line"], cHeaderVal)
			}
		}

		// Check that site matches Metadata site, if present.
		if m.site != "" && recordMap["site"] != m.site {
			return fmt.Errorf("line '%s' site '%s' does not match expected site '%s'", recordMap["line"], recordMap["site"], m.site)
		}

		// Check that model and version exist in the info retrieved from data
		// models service.
		for model, versionInfo := range m.serviceModels {

			versions := versionInfo["sorted"]

			if recordMap["cdm"] == model {

				mFound = true

				// Default to latest model version.
				if recordMap["cdm-version"] == "" {
					recordMap["cdm-version"] = versions[len(versions)-1]
					vFound = true
					break
				}

				for _, version := range versions {
					if recordMap["cdm-version"] == version {
						vFound = true
						break
					}
				}

				break
			}
		}

		if !mFound || !vFound {
			return fmt.Errorf("line '%s' cdm '%s' version '%s' not found in data models service", recordMap["line"], recordMap["cdm"], recordMap["cdm-version"])
		}

		// Check that model matches Metadata model, if present.
		if m.model != "" && recordMap["cdm"] != m.model {
			return fmt.Errorf("line '%s' cdm '%s' does not match expected model '%s'", recordMap["line"], recordMap["cdm"], m.model)
		}

		// Check that model version matches Metadata model version, if present.
		if m.modelVersion != "" && recordMap["cdm-version"] != m.modelVersion {
			return fmt.Errorf("line '%s' cdm-version '%s' does not match expected model version '%s'", recordMap["line"], recordMap["cdm-version"], m.modelVersion)
		}

		// Check that the table is present in the info retrieved from the data
		// models service.
		for _, table := range m.serviceModels[recordMap["cdm"]][recordMap["cdm-version"]] {
			if recordMap["table"] == table {
				tFound = true
				break
			}
		}

		if !tFound {
			return fmt.Errorf("line '%s' table '%s' not found in data models service", recordMap["line"], recordMap["table"])
		}

		// Check that data version matches Metadata data version, if both are
		// present.
		if m.dataVersion != "" && recordMap["data-version"] != "" && recordMap["data-version"] != m.dataVersion {
			return fmt.Errorf("line '%s' data-version '%s' does not match expected data version '%s'", recordMap["line"], recordMap["data-version"], m.dataVersion)
		}
	}

	// Validate record checksums.
	for _, recordMap := range m.recordMaps {

		var (
			dataFile  *os.File
			sum       hash.Hash
			sumString string
		)

		// Check that file exists.
		if dataFile, err = os.Open(filepath.Join(m.path, recordMap["filename"])); err != nil {
			return err
		}

		defer dataFile.Close()

		// Verify checksum.
		sum = sha256.New()

		log.Printf("packer: validating '%s' checksum", filepath.Base(recordMap["filename"]))

		if _, err = io.Copy(sum, dataFile); err != nil {
			return err
		}

		sumString = hex.EncodeToString(sum.Sum(nil))

		if recordMap["checksum"] != sumString {
			return fmt.Errorf("line '%s' file '%s' checksum does not match", recordMap["line"], recordMap["filename"])
		}
	}

	return nil
}

// Make writes metadata about data files in the Metadata directory to the
// passed writer and also stores them on the Metadata object. Any information
// missing from the Metadata object is collected through command line prompts.
func (m *Metadata) Make(w io.Writer) (err error) {

	var (
		modelChoices   []string
		versionChoices []string
		dataBuff       *bytes.Buffer
		multiWriter    io.Writer
		rowWriter      filepath.WalkFunc
	)

	// Write metadata to a buffer as well so it can be read back into the
	// Metadata object.
	dataBuff = new(bytes.Buffer)
	multiWriter = io.MultiWriter(dataBuff, w)

	// Collect site name (using empty choice list) if not on Metadata.
	if m.site == "" {
		var sites []string
		if m.site, err = collectInput("site name", sites); err != nil {
			return err
		}
	}

	// Create model and version choice lists from the info retrieved from data
	// models service.
	for model, versionInfo := range m.serviceModels {
		modelChoices = append(modelChoices, model)
		for _, version := range versionInfo["sorted"] {
			versionChoices = append(versionChoices, version)
		}
	}

	// Collect model if not on Metadata, using model choice list.
	if m.model == "" {
		if m.model, err = collectInput("common data model name", modelChoices); err != nil {
			return err
		}
		m.model = strings.ToLower(m.model)
	}

	// Collect model version if not on Metadata, using version choice list.
	if m.modelVersion == "" {
		if m.modelVersion, err = collectInput("model version", versionChoices); err != nil {
			return err
		}
		m.modelVersion = strings.ToLower(m.modelVersion)
	}

	// Collect etl URL (using empty choice list) if not passed.
	if m.etl == "" {
		var etls []string
		if m.etl, err = collectInput("etl code URL", etls); err != nil {
			return err
		}
	}

	// TODO: Implement data version tagging at sites.
	/*// Collect data version (using empty choice list) if not passed.
	if dataVersion == "" {
		var dataVersions []string
		dataVersion, err = collectInput("data version", dataVersions)
		if err != nil {
			return err
		}
	}*/

	// Write metadata header.
	m.header = canonicalHeader
	if _, err = m.writeHeader(multiWriter); err != nil {
		return err
	}

	// Make a walk function that will write metadata rows based on a
	// combination of the Metadata-stored information and the data files in the
	// directory.
	rowWriter = m.makeRowWriter(multiWriter)

	// Write metadata rows.
	if err = filepath.Walk(m.path, rowWriter); err != nil {
		return err
	}

	// Read the rows back into the Metadata object.
	if err = m.readData(dataBuff); err != nil {
		return err
	}

	return nil
}

// makeRowWriter uses a populated Metadata object to create a walk function
// that can be passed to filepath.Walk in order to write csv-formatted metadata
// rows to the passed writer.
func (m *Metadata) makeRowWriter(w io.Writer) (rowWriter filepath.WalkFunc) {

	return func(path string, fi os.FileInfo, inErr error) (err error) {

		var (
			relPath  string
			table    string
			tFound   bool
			dataFile *os.File
			sum      hash.Hash
		)

		// Return any error passed in.
		if err = inErr; err != nil {
			return err
		}

		// Get file path relative to the base data dir.
		if relPath, err = filepath.Rel(m.path, path); err != nil {
			return err
		}

		// Skip directories and the metadata file itself.
		if fi.IsDir() || relPath == "metadata.csv" {
			return nil
		}

		// Error if non-csv file found.
		if filepath.Ext(path) != ".csv" {
			return fmt.Errorf("non-csv file found: %s", path)
		}

		// If file name is present in the info retrieved from data models
		// service, use it. Otherwise, collect table name from STDIN.
		table = strings.TrimSuffix(filepath.Base(path), ".csv")

		for _, serviceTable := range m.serviceModels[m.model][m.modelVersion] {
			if table == serviceTable {
				tFound = true
				break
			}
		}

		if !tFound {
			if table, err = collectInput(fmt.Sprintf("table name for '%s'", path), m.serviceModels[m.model][m.modelVersion]); err != nil {
				return err
			}
			table = strings.ToLower(table)
		}

		// Calculate checksum.
		if dataFile, err = os.Open(path); err != nil {
			return err
		}

		defer dataFile.Close()

		sum = sha256.New()

		log.Printf("packer: calculating '%s' checksum", filepath.Base(path))
		if _, err = io.Copy(sum, dataFile); err != nil {
			return err
		}

		sumString := hex.EncodeToString(sum.Sum(nil))

		// Write metadata row.
		if _, err = w.Write([]byte(fmt.Sprintf("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n", m.site, relPath, sumString, m.model, m.modelVersion, table, m.etl, m.dataVersion))); err != nil {
			return err
		}

		return nil
	}
}

// writeHeader writes uses m.header to write a csv-formatted header to the
// passed writer.
func (m *Metadata) writeHeader(w io.Writer) (n int, err error) {
	return w.Write([]byte(fmt.Sprintf("\"%s\"\n", strings.Join(m.header, `","`))))
}

// collectInput collects command line input using a provided prompt string. If
// a choices list is passed, the user will be prompted repeatedely until they
// provide one of the choices.
func collectInput(prompt string, choices []string) (input string, err error) {

	for {

		fmt.Printf("Please provide %s: ", prompt)
		fmt.Scanln(&input)

		if len(choices) > 0 {

			found := false

			for _, choice := range choices {
				if strings.ToLower(input) == choice {
					found = true
				}
			}

			if !found {
				fmt.Printf("Invalid input, please choose from '%s'.\n", strings.Join(choices, ", "))
				continue
			}
		}

		break
	}

	return input, nil
}
