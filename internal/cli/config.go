package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"
)

// UserConfig is the per-user CLI config (feature 01 5.1), mode 0600.
type UserConfig struct {
	Server   string `yaml:"server,omitempty"`
	Token    string `yaml:"token,omitempty"`
	Tenant   string `yaml:"tenant,omitempty"`
	CAFile   string `yaml:"ca_file,omitempty"`
	Insecure bool   `yaml:"insecure,omitempty"`
}

// ProjectContext is .rypt-store.yaml: no credentials, safe to commit.
type ProjectContext struct {
	Server      string `yaml:"server,omitempty"`
	Tenant      string `yaml:"tenant,omitempty"`
	Project     string `yaml:"project,omitempty"`
	Environment string `yaml:"environment,omitempty"`
}

// ContextFile is the project context file name.
const ContextFile = ".rypt-store.yaml"

// userConfigPath honours RYPT_STORE_CLI_CONFIG, else
// <UserConfigDir>/rypt-store/config.yaml.
func userConfigPath(getenv func(string) string) (string, error) {
	if p := getenv("RYPT_STORE_CLI_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "rypt-store", "config.yaml"), nil
}

func loadUserConfig(path string) (*UserConfig, error) {
	var c UserConfig
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return &c, nil
	}
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &c, nil
}

func saveUserConfig(path string, c *UserConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	// WriteFile keeps an existing file's mode; force 0600.
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// findContext looks for .rypt-store.yaml in dir and its parents.
func findContext(dir string) (*ProjectContext, string, error) {
	for {
		p := filepath.Join(dir, ContextFile)
		b, err := os.ReadFile(p)
		if err == nil {
			var c ProjectContext
			if err := yaml.Unmarshal(b, &c); err != nil {
				return nil, "", fmt.Errorf("parse %s: %w", p, err)
			}
			return &c, p, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, "", err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return &ProjectContext{}, "", nil
		}
		dir = parent
	}
}

func writeContext(path string, c *ProjectContext) error {
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	header := "# rypt-store project context. It holds no credentials and is safe to commit.\n"
	return os.WriteFile(path, append([]byte(header), b...), 0o644)
}
