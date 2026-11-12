package capif

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// state is what the AF keeps of its onboarding at the CAPIF core function
// (TS 33.122 cl. 6.1 step 5), in a file that only its user can read.
type state struct {
	CcfURI           string `json:"ccfUri"`
	APIInvokerID     string `json:"apiInvokerId"`
	Certificate      string `json:"apiInvokerCertificate"`
	PrivateKey       string `json:"privateKey"`
	OnboardingSecret string `json:"onboardingSecret"`
}

// loadState reads the state at path; nil when there is none.
func loadState(path string) (*state, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	var st state
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("state %s: %w", path, err)
	}
	if st.APIInvokerID == "" || st.Certificate == "" || st.PrivateKey == "" || st.OnboardingSecret == "" {
		return nil, fmt.Errorf("state %s: incomplete", path)
	}
	return &st, nil
}

// saveState writes the state at path with permission 0600, through a
// temporary file in the same directory.
func saveState(path string, st *state) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("state: %w", err)
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".capif-state-*")
	if err != nil {
		return fmt.Errorf("state: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("state: %w", err)
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return fmt.Errorf("state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("state: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("state: %w", err)
	}
	return nil
}

// removeState deletes the state at path.
func removeState(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("state: %w", err)
	}
	return nil
}
