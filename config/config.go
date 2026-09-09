package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/knadh/koanf/parsers/toml/v2"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
	"gopkg.in/hlandau/easyconfig.v1/adaptflag"
	"gopkg.in/hlandau/svcutils.v1/exepath"
)

type Loader struct {
	programName    string
	configFilePath string
	confFlag       string
}

var (
	errInvalidTarget     = errors.New("config target must be a pointer to a struct")
	errUnassignableField = errors.New("config field is not assignable")
	errUnsupportedField  = errors.New("unsupported config field")
)

func New(programName string) *Loader {
	if exepath.ProgramNameSetter == "default" && programName != "" {
		exepath.ProgramName = programName
	}

	l := &Loader{programName: programName}
	flag.StringVar(&l.confFlag, "conf", "", "Configuration file path")

	return l
}

func (l *Loader) Register(group string, target any) error {
	v := reflect.ValueOf(target)
	if v.Kind() != reflect.Pointer || v.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("config target for %s: %w", group, errInvalidTarget)
	}

	t := v.Elem().Type()
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		usage := field.Tag.Get("usage")
		dflt := field.Tag.Get("default")
		if usage == "" && dflt == "" {
			continue
		}

		name := group + "." + strings.ToLower(field.Name)
		value := v.Elem().Field(i)
		if !value.CanSet() {
			return fmt.Errorf("%s: %w", name, errUnassignableField)
		}

		//nolint:exhaustive // ncdns config structs only use these types.
		switch value.Kind() {
		case reflect.String:
			value.SetString(dflt)
			flag.StringVar(value.Addr().Interface().(*string), name, dflt, usage)
		case reflect.Int:
			n := 0
			if dflt != "" {
				var err error
				n, err = strconv.Atoi(dflt)
				if err != nil {
					return fmt.Errorf("invalid default for %s: %w", name, err)
				}
			}
			value.SetInt(int64(n))
			flag.IntVar(value.Addr().Interface().(*int), name, n, usage)
		case reflect.Bool:
			b := false
			if dflt != "" {
				var err error
				b, err = strconv.ParseBool(dflt)
				if err != nil {
					return fmt.Errorf("invalid default for %s: %w", name, err)
				}
			}
			value.SetBool(b)
			flag.BoolVar(value.Addr().Interface().(*bool), name, b, usage)
		default:
			return fmt.Errorf("%s (%s): %w", name, value.Kind(), errUnsupportedField)
		}
	}

	return nil
}

func (l *Loader) Parse() error {
	adaptflag.Adapt()
	flag.Parse()

	configFilePath := l.findConfigFilePath()
	if configFilePath == "" {
		return nil
	}

	paths, err := configFiles(configFilePath)
	if err != nil {
		return err
	}

	k := koanf.New(".")
	for _, path := range paths {
		if err := k.Load(file.Provider(path), toml.Parser()); err != nil {
			return fmt.Errorf("error decoding %s: %w", path, err)
		}
	}

	setFlags := make(map[string]bool)
	flag.CommandLine.Visit(func(f *flag.Flag) {
		setFlags[f.Name] = true
	})

	for _, key := range k.Keys() {
		if setFlags[key] || flag.Lookup(key) == nil {
			continue
		}

		if err := flag.Set(key, fmt.Sprint(k.Get(key))); err != nil {
			return fmt.Errorf("invalid value for %s: %w", key, err)
		}
	}

	l.configFilePath = configFilePath

	return nil
}

func (l *Loader) ParseFatal() {
	if err := l.Parse(); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot load configuration file: %v\n", err)
		os.Exit(1)
	}
}

func (l *Loader) ConfigFilePath() string {
	return l.configFilePath
}

func (l *Loader) findConfigFilePath() string {
	if l.confFlag != "" {
		return l.confFlag
	}

	var configFilePath string
	for _, path := range []string{
		fmt.Sprintf("/etc/%s/%s.conf", l.programName, l.programName),
		fmt.Sprintf("/etc/%s.conf", l.programName),
		fmt.Sprintf("etc/%s.conf", l.programName),
		fmt.Sprintf("$BIN/%s.conf", l.programName),
		fmt.Sprintf("$BIN/../etc/%s/%s.conf", l.programName, l.programName),
		fmt.Sprintf("$BIN/../etc/%s.conf", l.programName),
	} {
		path = expandPath(path)
		if pathExists(path) {
			configFilePath = path
		}
	}

	return configFilePath
}

func configFiles(configFilePath string) ([]string, error) {
	var paths []string

	_, mainErr := os.Stat(configFilePath)
	if mainErr == nil {
		paths = append(paths, configFilePath)
	}

	_, dirErr := os.Stat(configFilePath + ".d")
	if dirErr == nil {
		fragments, err := filepath.Glob(configFilePath + ".d/*.conf")
		if err != nil {
			return nil, fmt.Errorf("globbing error: %w", err)
		}
		paths = append(paths, fragments...)
	}

	if mainErr != nil && dirErr != nil {
		return nil, fmt.Errorf("error finding conf file: %w; %v", mainErr, dirErr)
	}

	return paths, nil
}

func pathExists(path string) bool {
	if _, err := os.Stat(path); err == nil {
		return true
	}

	_, err := os.Stat(path + ".d")

	return err == nil
}

func expandPath(path string) string {
	if !strings.HasPrefix(path, "$BIN/") {
		return path
	}

	return filepath.Join(filepath.Dir(exepath.Abs), path[5:])
}
