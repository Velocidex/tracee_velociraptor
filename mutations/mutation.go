package mutations

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/goccy/go-yaml"
	"github.com/magefile/mage/sh"
)

type mutation struct {
	Description string `json:"Desc"`

	// Copy files
	From        string `json:"From"`
	To          string `json:"To"`
	StripPrefix string `json:"StripPrefix"`

	// Go Replace by regex
	Match   string `json:"Match"`
	Replace string `json:"Replace"`
	Glob    string `json:"Glob"`

	DeleteGlob string `json:"DeleteGlob"`
}

type mutationFile struct {
	verbose bool

	ExcludedFiles     []string `json:"ExcludedFiles"`
	excluded_file_res []*regexp.Regexp
	Mutations         []mutation `json:"Mutations"`
}

func LoadMutations(filename string) (*mutationFile, error) {
	fd, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(fd)
	if err != nil {
		return nil, err
	}

	res := &mutationFile{}
	err = yaml.Unmarshal(data, res)
	if err != nil {
		return nil, err
	}

	for _, e := range res.ExcludedFiles {
		re, err := regexp.Compile(e)
		if err != nil {
			return nil, err
		}
		res.excluded_file_res = append(res.excluded_file_res, re)
	}

	return res, err
}

func (self *mutationFile) LogDebug(message string, args ...interface{}) {
	if self.verbose {
		fmt.Printf(message, args...)
	}
}

func (self *mutationFile) LogInfo(message string, args ...interface{}) {
	fmt.Printf(message, args...)
}

func (self *mutationFile) isFilenameExcluded(name string) bool {
	for _, e := range self.excluded_file_res {
		if e.MatchString(name) {
			return true
		}
	}
	return false
}

func (self *mutationFile) Copy(dest, src string) error {
	dirname := filepath.Dir(dest)
	os.MkdirAll(dirname, 0755)

	return sh.Copy(dest, src)
}

func (self *mutationFile) ApplyMutations() error {
	for _, m := range self.Mutations {
		if m.From != "" {
			self.LogInfo("%v: Copying %v to %v\n",
				m.Description, m.From, m.To)
			fsys := os.DirFS(".")
			matches, err := doublestar.Glob(fsys, m.From)
			if err != nil {
				return err
			}

			for _, match := range matches {
				if self.isFilenameExcluded(match) {
					continue
				}

				fileInfo, err := os.Stat(match)
				if err != nil {
					continue
				}
				if fileInfo.IsDir() {
					continue
				}
				output_filename := filepath.Base(match)
				if m.StripPrefix != "" {
					output_filename = strings.TrimPrefix(match, m.StripPrefix)
				}
				output := filepath.Join(m.To, output_filename)
				self.LogDebug("  %v->%v\n", match, output)
				err = self.Copy(output, match)
				if err != nil {
					return err
				}
			}
		}

		if m.DeleteGlob != "" {
			basepath, pattern := doublestar.SplitPattern(m.DeleteGlob)
			self.LogInfo("%v: Deleting %v\n", m.Description, m.DeleteGlob)
			fsys := os.DirFS(basepath)
			matches, err := doublestar.Glob(fsys, pattern)
			if err != nil {
				return err
			}

			for _, match := range matches {
				filename := filepath.Join(basepath, match)
				self.LogDebug("  Deleting %v in %v\n", m.Match, filename)
				err = os.Remove(filename)
				if err != nil {
					return err
				}
			}
		}

		if m.Glob != "" {
			basepath, pattern := doublestar.SplitPattern(m.Glob)
			self.LogInfo("%v: Replacing %v in %v\n",
				m.Description, m.Match, m.Glob)

			fsys := os.DirFS(basepath)
			matches, err := doublestar.Glob(fsys, pattern)
			if err != nil {
				return err
			}

			for _, match := range matches {
				filename := filepath.Join(basepath, match)
				err = replace_regex_in_file(filename, m.Match, m.Replace)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func replace_regex_in_file(filename string, old string, new string) error {
	old_re, err := regexp.Compile(old)
	if err != nil {
		return err
	}

	read, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	newContents := old_re.ReplaceAll(read, []byte(new))
	return ioutil.WriteFile(filename, newContents, 0644)
}
