package config

import (
	"bytes"
	"cmp"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"

	"github.com/BurntSushi/toml"
	"github.com/riraccuia/pig/pkg/adapter"
)

func newAdapterSettings(adapterType string) (any, error) {
	switch adapter.AdapterType(adapterType) {
	case adapter.AdapterTypeTun:
		return &AdapterTunConfig{}, nil
	case adapter.AdapterTypeStdio:
		return &AdapterStdIOConfig{}, nil
	case adapter.AdapterTypeHTTPProxy:
		return &AdapterHTTPProxyConfig{}, nil
	}
	return nil, fmt.Errorf("invalid adapter type: %q", adapterType)
}

func (a *AdapterConfig) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	rawVal, err := dec.ReadValue()
	if err != nil {
		return err
	}
	var raw struct {
		AdapterType   string         `json:"adapter_type"`
		AdapterConfig jsontext.Value `json:"adapter_config"`
	}
	if err := json.Unmarshal(rawVal, &raw); err != nil {
		return err
	}
	adapterType := cmp.Or(raw.AdapterType, string(adapter.AdapterTypeTun))
	settings, err := newAdapterSettings(adapterType)
	if err != nil {
		return err
	}
	if len(raw.AdapterConfig) > 0 {
		if err := json.Unmarshal(raw.AdapterConfig, settings); err != nil {
			return fmt.Errorf("adapter %s: %w", adapterType, err)
		}
	}
	a.AdapterType = adapterType
	a.AdapterConfig = settings
	return nil
}

func (a *AdapterConfig) UnmarshalTOML(data any) error {
	table, ok := data.(map[string]any)
	if !ok {
		return fmt.Errorf("adapter: expected a table, got %T", data)
	}
	rawType, present := table["adapter_type"]
	adapterType, isString := rawType.(string)
	if present && !isString {
		return fmt.Errorf("adapter_type: expected a string, got %T", rawType)
	}
	adapterType = cmp.Or(adapterType, string(adapter.AdapterTypeTun))
	settings, err := newAdapterSettings(adapterType)
	if err != nil {
		return err
	}
	if sub, present := table["adapter_config"]; present {
		if err := decodeTOMLTable(sub, settings); err != nil {
			return fmt.Errorf("adapter %s: %w", adapterType, err)
		}
	}
	a.AdapterType = adapterType
	a.AdapterConfig = settings
	return nil
}

// decodeTOMLTable decodes a table already parsed by the toml package into v.
// The package exposes no map-to-struct decoder, so the table is re-encoded.
func decodeTOMLTable(table any, v any) error {
	m, ok := table.(map[string]any)
	if !ok {
		return fmt.Errorf("expected a table, got %T", table)
	}
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(m); err != nil {
		return err
	}
	_, err := toml.Decode(buf.String(), v)
	return err
}

func (ic *ICEConfig) IsZero() bool {
	if ic == nil {
		return true
	}
	if !ic.Enabled {
		return true
	}
	return false
}
