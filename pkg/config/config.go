package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// envVarRegex is a regular expression to match environment variable placeholders in the form ${VAR_NAME}.
var envVarRegex = regexp.MustCompile(`\$\{([^}]+)\}`)

// ProcessorOptions configures the YAML processor behavior
type ProcessorOptions struct {
	EnableEnvVarExpansion bool
	EnableFileTag         bool
	BaseDir               string
	RequireEnvVars        bool
}

// DefaultOptions returns default processor options with all features enabled
func DefaultOptions() ProcessorOptions {
	return ProcessorOptions{
		EnableEnvVarExpansion: true,
		EnableFileTag:         true,
		RequireEnvVars:        true,
	}
}

// Processor handles YAML processing with environment variable expansion and custom tags
type Processor struct {
	options ProcessorOptions
}

// NewProcessor creates a new YAML processor with the given options
func NewProcessor(options ProcessorOptions) *Processor {
	return &Processor{
		options: options,
	}
}

// NewDefaultProcessor creates a processor with default options
func NewDefaultProcessor() *Processor {
	return NewProcessor(DefaultOptions())
}

// LoadFile loads and processes a YAML file, returning the processed node
func (p *Processor) LoadFile(path string) (*yaml.Node, error) {
	rawYAML, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read YAML file '%s': %w", path, err)
	}

	if p.options.BaseDir == "" {
		absPath, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("resolve file path: %w", err)
		}
		p.options.BaseDir = filepath.Dir(absPath)
	}

	return p.ProcessBytes(rawYAML)
}

// ProcessBytes processes raw YAML bytes and returns the processed node
func (p *Processor) ProcessBytes(rawYAML []byte) (*yaml.Node, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(rawYAML, &root); err != nil {
		return nil, fmt.Errorf("unmarshal YAML: %w", err)
	}

	if len(root.Content) == 0 {
		return nil, fmt.Errorf("YAML content is empty")
	}

	if err := p.processNode(root.Content[0]); err != nil {
		return nil, fmt.Errorf("process YAML nodes: %w", err)
	}

	return &root, nil
}

// ProcessString processes a YAML string and returns the processed node
func (p *Processor) ProcessString(yamlStr string) (*yaml.Node, error) {
	return p.ProcessBytes([]byte(yamlStr))
}

// LoadAndDecode loads a YAML file, processes it, and decodes into the target struct
func (p *Processor) LoadAndDecode(path string, target interface{}) error {
	node, err := p.LoadFile(path)
	if err != nil {
		return err
	}

	if err := node.Decode(target); err != nil {
		return fmt.Errorf("decode YAML: %w", err)
	}

	return nil
}

// ProcessAndDecode processes YAML bytes and decodes into the target struct
func (p *Processor) ProcessAndDecode(rawYAML []byte, target interface{}) error {
	node, err := p.ProcessBytes(rawYAML)
	if err != nil {
		return err
	}

	if err := node.Decode(target); err != nil {
		return fmt.Errorf("decode YAML: %w", err)
	}

	return nil
}

// processNode recursively processes a YAML node, expanding environment variables
// and handling custom tags like !file.
func (p *Processor) processNode(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		if p.options.EnableEnvVarExpansion {
			val, err := p.expandEnvVars(node.Value)
			if err != nil {
				return fmt.Errorf("expand env vars in '%s': %w", node.Value, err)
			}
			node.Value = val
		}

		if p.options.EnableFileTag && node.Tag == "!file" {
			if err := p.processFileTag(node); err != nil {
				return err
			}
		}

	case yaml.SequenceNode, yaml.MappingNode:
		for _, n := range node.Content {
			if err := p.processNode(n); err != nil {
				return err
			}
		}
	}
	return nil
}

// processFileTag handles the !file custom tag
func (p *Processor) processFileTag(node *yaml.Node) error {
	path := node.Value

	if !filepath.IsAbs(path) && p.options.BaseDir != "" {
		path = filepath.Join(p.options.BaseDir, path)
	}

	content, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("read !file '%s': %w", path, err)
	}

	node.Tag = "!!str"
	node.Value = strings.TrimSpace(string(content))
	return nil
}

// expandEnvVars replaces environment variable placeholders in the input string
// with their actual values.
func (p *Processor) expandEnvVars(input string) (string, error) {
	result := input
	matches := envVarRegex.FindAllStringSubmatch(result, -1)

	for _, match := range matches {
		placeholder := match[0]
		varName := match[1]
		val, exists := os.LookupEnv(varName)

		if !exists {
			if p.options.RequireEnvVars {
				return "", fmt.Errorf("environment variable '%s' not set", varName)
			}
			continue
		}

		result = strings.ReplaceAll(result, placeholder, val)
	}

	return result, nil
}

// Convenience functions for common use cases

// LoadConfig is a convenience function that loads and processes a config file
func LoadConfig(path string, target interface{}) error {
	processor := NewDefaultProcessor()
	return processor.LoadAndDecode(path, target)
}

// LoadConfigWithOptions loads a config file with custom processor options
func LoadConfigWithOptions(path string, target interface{}, options ProcessorOptions) error {
	processor := NewProcessor(options)
	return processor.LoadAndDecode(path, target)
}

// ProcessYAMLString processes a YAML string with default options
func ProcessYAMLString(yamlStr string, target interface{}) error {
	processor := NewDefaultProcessor()
	return processor.ProcessAndDecode([]byte(yamlStr), target)
}
