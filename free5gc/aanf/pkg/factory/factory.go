/*
 * AAnF Configuration Factory
 */

package factory

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"

	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/internal/logger"
)

var AanfConfig *Config

// InitConfigFactory reads the configuration file f into cfg.
func InitConfigFactory(f string, cfg *Config) error {
	if f == "" {
		f = AanfDefaultConfigPath
	}

	content, err := os.ReadFile(f)
	if err != nil {
		return fmt.Errorf("[Factory] %+v", err)
	}
	logger.CfgLog.Infof("Read config from [%s]", f)
	if err = yaml.Unmarshal(content, cfg); err != nil {
		return fmt.Errorf("[Factory] %+v", err)
	}
	return nil
}

// ReadConfig reads and validates the configuration file.
func ReadConfig(cfgPath string) (*Config, error) {
	cfg := &Config{}
	if err := InitConfigFactory(cfgPath, cfg); err != nil {
		return nil, fmt.Errorf("ReadConfig [%s] Error: %+v", cfgPath, err)
	}
	if _, err := cfg.Validate(); err != nil {
		logger.CfgLog.Errorf("[-- PLEASE REFER TO SAMPLE CONFIG FILE COMMENTS --]")
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	return cfg, nil
}
