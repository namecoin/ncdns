package config

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/knadh/koanf/parsers/toml/v2"
	"github.com/knadh/koanf/providers/basicflag"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
	"gopkg.in/hlandau/configurable.v1"
	"gopkg.in/hlandau/svcutils.v1/exepath"
)

type Loader struct {
	programName    string
	configFilePath string
	registered     []registered
	confFlag       string
}

type registered struct {
	group  string
	target interface{}
}

func New(programName string) *Loader {
	if exepath.ProgramNameSetter == "default" && programName != "" {
		exepath.ProgramName = programName
	}

	l := &Loader{programName: programName}
	flag.StringVar(&l.confFlag, "conf", "", "Configuration file path")
	return l
}

func (l *Loader) Register(group string, target interface{}) error {
	v := reflect.ValueOf(target)
	if v.Kind() != reflect.Ptr || v.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("config target for %s must be a pointer to a struct", group)
	}

	t := v.Elem().Type()
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		usage := field.Tag.Get("usage")
		dflt := field.Tag.Get("default")
		if usage == "" && dflt == "" {
			continue
		}

		key := group + "." + strings.ToLower(field.Name)
		if err := registerFlag(key, dflt, usage, field.Type.Kind()); err != nil {
			return err
		}
		if dflt != "" {
			setField(v.Elem().Field(i), dflt)
		}
	}

	l.registered = append(l.registered, registered{group: group, target: target})
	return nil
}

func (l *Loader) Parse() error {
	l.adaptConfigurableFlags()
	flag.Parse()

	k := koanf.New(".")
	configFilePath := l.findConfigFilePath()
	if configFilePath != "" {
		paths, err := configFiles(configFilePath)
		if err != nil {
			return err
		}
		for _, path := range paths {
			if err := k.Load(file.Provider(path), toml.Parser()); err != nil {
				return fmt.Errorf("Error decoding %s: %w", path, err)
			}
			l.configFilePath = configFilePath
		}
	}

	if err := k.Load(basicflag.Provider(flag.CommandLine, ".", &basicflag.Opt{KeyMap: k}), nil); err != nil {
		return err
	}

	for _, r := range l.registered {
		applyRegistered(k, r)
	}
	l.applyConfigurables(k)

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

func registerFlag(key, dflt, usage string, kind reflect.Kind) error {
	switch kind {
	case reflect.String:
		flag.String(key, dflt, usage)
	case reflect.Int:
		n, err := strconv.Atoi(dflt)
		if err != nil {
			return err
		}
		flag.Int(key, n, usage)
	case reflect.Bool:
		b := boolFlag(parseBool(dflt))
		flag.Var(&b, key, usage)
	default:
		return fmt.Errorf("unsupported config field type for %s: %s", key, kind)
	}
	return nil
}

type boolFlag bool

func (b *boolFlag) String() string {
	return strconv.FormatBool(bool(*b))
}

func (b *boolFlag) Set(s string) error {
	*b = boolFlag(parseBool(s))
	return nil
}

func (b *boolFlag) IsBoolFlag() bool {
	return true
}

func parseBool(s string) bool {
	switch s = strings.ToLower(strings.TrimSpace(s)); s {
	case "", "n", "no", "f", "false":
		return false
	}
	return strings.Trim(s, "0") != ""
}

func applyRegistered(k *koanf.Koanf, r registered) {
	v := reflect.ValueOf(r.target).Elem()
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if field.Tag.Get("usage") == "" && field.Tag.Get("default") == "" {
			continue
		}
		key := r.group + "." + strings.ToLower(field.Name)
		if !k.Exists(key) {
			continue
		}
		setField(v.Field(i), k.Get(key))
	}
}

func setField(field reflect.Value, value interface{}) {
	switch field.Kind() {
	case reflect.String:
		if s, ok := value.(string); ok {
			field.SetString(s)
		}
	case reflect.Int:
		setIntField(field, value)
	case reflect.Bool:
		setBoolField(field, value)
	}
}

func setIntField(field reflect.Value, value interface{}) {
	switch v := value.(type) {
	case int:
		field.SetInt(int64(v))
	case int64:
		field.SetInt(v)
	case string:
		if n, err := strconv.ParseInt(strings.TrimSpace(v), 0, 32); err == nil {
			field.SetInt(n)
		}
	}
}

func setBoolField(field reflect.Value, value interface{}) {
	switch v := value.(type) {
	case bool:
		field.SetBool(v)
	case int:
		field.SetBool(v != 0)
	case int64:
		field.SetBool(v != 0)
	case string:
		field.SetBool(parseBool(v))
	}
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
	paths := []string{}

	_, mainStatErr := os.Stat(configFilePath)
	if mainStatErr == nil {
		paths = append(paths, configFilePath)
	}

	_, globStatErr := os.Stat(configFilePath + ".d")
	if globStatErr == nil {
		globResult, err := filepath.Glob(configFilePath + ".d/*.conf")
		if err != nil {
			return nil, fmt.Errorf("Globbing error: %s", err)
		}
		paths = append(paths, globResult...)
	}

	if mainStatErr != nil && globStatErr != nil {
		return nil, fmt.Errorf("Error finding conf file: %s, %s", mainStatErr, globStatErr)
	}

	return paths, nil
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}

	_, err = os.Stat(path + ".d")
	return err == nil
}

func expandPath(path string) string {
	if !strings.HasPrefix(path, "$BIN/") {
		return path
	}

	return filepath.Join(filepath.Dir(exepath.Abs), path[5:])
}

type configurableValue struct {
	c configurable.Configurable
}

func (v *configurableValue) String() string {
	if cv, ok := v.c.(interface{ CfValue() interface{} }); ok {
		return fmt.Sprintf("%v", cv.CfValue())
	}
	if dflt, ok := v.c.(interface{ CfDefaultValue() interface{} }); ok {
		return fmt.Sprintf("%v", dflt.CfDefaultValue())
	}
	return ""
}

func (v *configurableValue) Set(s string) error {
	return setConfigurable(v.c, s, configurable.FlagPriority)
}

func (v *configurableValue) IsBoolFlag() bool {
	cv, ok := v.c.(interface{ CfValue() interface{} })
	if !ok {
		return false
	}
	_, ok = cv.CfValue().(bool)
	return ok
}

func (l *Loader) adaptConfigurableFlags() {
	configurable.Visit(func(c configurable.Configurable) error {
		l.adaptConfigurableFlag(nil, c)
		return nil
	})
}

func (l *Loader) adaptConfigurableFlag(path []string, c configurable.Configurable) {
	name, hasName := configurableName(c)
	keyPath := path
	if hasName {
		keyPath = append(append([]string{}, path...), name)
	}

	if len(keyPath) > 0 {
		if _, ok := c.(interface{ CfSetValue(interface{}) error }); ok {
			usage := ""
			if u, ok := c.(interface{ CfUsageSummaryLine() string }); ok {
				usage = u.CfUsageSummaryLine()
			}
			flag.Var(&configurableValue{c: c}, strings.Join(keyPath, "."), usage)
		}
	}

	if cc, ok := c.(interface {
		CfChildren() []configurable.Configurable
	}); ok {
		for _, child := range cc.CfChildren() {
			l.adaptConfigurableFlag(keyPath, child)
		}
	}
}

func (l *Loader) applyConfigurables(k *koanf.Koanf) {
	configurable.Visit(func(c configurable.Configurable) error {
		applyConfigurable(k, nil, c)
		return nil
	})
}

func applyConfigurable(k *koanf.Koanf, path []string, c configurable.Configurable) {
	name, hasName := configurableName(c)
	keyPath := path
	if hasName {
		keyPath = append(append([]string{}, path...), name)
	}
	key := strings.Join(keyPath, ".")

	if key != "" && k.Exists(key) {
		value := k.Get(key)
		_ = setConfigurable(c, value, configurable.ConfigPriority)
	}

	if cc, ok := c.(interface {
		CfChildren() []configurable.Configurable
	}); ok {
		for _, child := range cc.CfChildren() {
			applyConfigurable(k, keyPath, child)
		}
	}
}

func configurableName(c configurable.Configurable) (string, bool) {
	cn, ok := c.(interface{ CfName() string })
	if !ok {
		return "", false
	}

	return cn.CfName(), true
}

func setConfigurable(c configurable.Configurable, value interface{}, priority configurable.Priority) error {
	cs, ok := c.(interface{ CfSetValue(interface{}) error })
	if !ok {
		return fmt.Errorf("configurable does not accept values")
	}

	cp, ok := c.(interface {
		CfGetPriority() configurable.Priority
		CfSetPriority(configurable.Priority)
	})
	if ok && cp.CfGetPriority() > priority {
		return nil
	}
	if err := cs.CfSetValue(value); err != nil {
		return err
	}
	if ok {
		cp.CfSetPriority(priority)
	}
	return nil
}
