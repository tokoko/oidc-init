package profiles

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	profileDir  = ".oidc"
	profileFile = "profiles.json"
	defaultKey  = "_default"
	filePerms   = 0600
	dirPerms    = 0700
)

// Profile holds the configuration for an OIDC provider.
type Profile struct {
	Endpoint     string `json:"endpoint"`
	Realm        string `json:"realm"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	Scope        string `json:"scope"`
	Protocol     string `json:"protocol"`
	Flow         string `json:"flow"`
	Verify       bool   `json:"verify"`
	Username     string `json:"username,omitempty"`
}

// Manager provides CRUD operations on the profiles file.
type Manager struct {
	path string
}

// NewManager returns a Manager that reads/writes ~/.oidc/profiles.json.
func NewManager() (*Manager, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("cannot determine home directory: %w", err)
	}
	dir := filepath.Join(home, profileDir)
	if err := os.MkdirAll(dir, dirPerms); err != nil {
		return nil, fmt.Errorf("cannot create profile directory: %w", err)
	}
	return &Manager{path: filepath.Join(dir, profileFile)}, nil
}

// load reads the raw JSON map from disk. Returns an empty map if the file
// does not exist.
func (m *Manager) load() (map[string]json.RawMessage, error) {
	data, err := os.ReadFile(m.path)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]json.RawMessage), nil
		}
		return nil, fmt.Errorf("failed to read profiles: %w", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse profiles: %w", err)
	}
	return raw, nil
}

// save writes the raw JSON map back to disk.
func (m *Manager) save(raw map[string]json.RawMessage) error {
	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal profiles: %w", err)
	}
	return os.WriteFile(m.path, data, filePerms)
}

// Add creates a new profile. If overwrite is true an existing profile with the
// same name will be replaced.
func (m *Manager) Add(name string, p *Profile, overwrite bool) error {
	if strings.HasPrefix(name, "_") {
		return fmt.Errorf("profile names starting with '_' are reserved")
	}
	raw, err := m.load()
	if err != nil {
		return err
	}
	if _, exists := raw[name]; exists && !overwrite {
		return fmt.Errorf("profile %q already exists (use --overwrite to replace)", name)
	}
	pBytes, err := json.Marshal(p)
	if err != nil {
		return err
	}
	raw[name] = pBytes
	return m.save(raw)
}

// Get returns the named profile.
func (m *Manager) Get(name string) (*Profile, error) {
	raw, err := m.load()
	if err != nil {
		return nil, err
	}
	pRaw, ok := raw[name]
	if !ok {
		return nil, fmt.Errorf("profile %q not found", name)
	}
	var p Profile
	if err := json.Unmarshal(pRaw, &p); err != nil {
		return nil, fmt.Errorf("failed to parse profile %q: %w", name, err)
	}
	return &p, nil
}

// List returns all profile names sorted alphabetically.
func (m *Manager) List() ([]string, error) {
	raw, err := m.load()
	if err != nil {
		return nil, err
	}
	var names []string
	for k := range raw {
		if strings.HasPrefix(k, "_") {
			continue
		}
		names = append(names, k)
	}
	sort.Strings(names)
	return names, nil
}

// Delete removes a profile by name.
func (m *Manager) Delete(name string) error {
	raw, err := m.load()
	if err != nil {
		return err
	}
	if _, ok := raw[name]; !ok {
		return fmt.Errorf("profile %q not found", name)
	}
	delete(raw, name)

	// If this was the default, unset it.
	if def, ok := raw[defaultKey]; ok {
		var defName string
		if json.Unmarshal(def, &defName) == nil && defName == name {
			delete(raw, defaultKey)
		}
	}

	return m.save(raw)
}

// Exists returns true if the named profile exists.
func (m *Manager) Exists(name string) bool {
	raw, err := m.load()
	if err != nil {
		return false
	}
	_, ok := raw[name]
	return ok
}

// SetDefault marks a profile as the default.
func (m *Manager) SetDefault(name string) error {
	raw, err := m.load()
	if err != nil {
		return err
	}
	if _, ok := raw[name]; !ok {
		return fmt.Errorf("profile %q not found", name)
	}
	defBytes, _ := json.Marshal(name)
	raw[defaultKey] = defBytes
	return m.save(raw)
}

// UnsetDefault removes the default profile setting.
func (m *Manager) UnsetDefault() error {
	raw, err := m.load()
	if err != nil {
		return err
	}
	if _, ok := raw[defaultKey]; !ok {
		return fmt.Errorf("no default profile is set")
	}
	delete(raw, defaultKey)
	return m.save(raw)
}

// GetDefault returns the name of the default profile, or empty string if none.
func (m *Manager) GetDefault() (string, error) {
	raw, err := m.load()
	if err != nil {
		return "", err
	}
	defRaw, ok := raw[defaultKey]
	if !ok {
		return "", nil
	}
	var name string
	if err := json.Unmarshal(defRaw, &name); err != nil {
		return "", fmt.Errorf("failed to parse default profile: %w", err)
	}
	return name, nil
}
