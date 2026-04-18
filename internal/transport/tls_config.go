// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package transport

import (
	"encoding/json"
	"fmt"
	"net"

	"gopkg.in/yaml.v3"
)

// OptionalString is a tri-state string used for config fields that must
// distinguish between:
// 1. not set,
// 2. explicitly null,
// 3. a concrete string value.
type OptionalString struct {
	set   bool
	value *string
}

func (o OptionalString) IsZero() bool {
	return !o.set
}

func (o OptionalString) IsSet() bool {
	return o.set
}

func (o OptionalString) Value() *string {
	if o.value == nil {
		return nil
	}
	v := *o.value
	return &v
}

func (o *OptionalString) UnmarshalYAML(value *yaml.Node) error {
	o.set = true
	if value.Tag == "!!null" || (value.Kind == yaml.ScalarNode && value.Value == "null") {
		o.value = nil
		return nil
	}
	var v string
	if err := value.Decode(&v); err != nil {
		return err
	}
	o.value = &v
	return nil
}

func (o OptionalString) MarshalYAML() (any, error) {
	if !o.set {
		return nil, nil
	}
	if o.value == nil {
		return nil, nil
	}
	return *o.value, nil
}

func (o *OptionalString) UnmarshalJSON(data []byte) error {
	o.set = true
	if string(data) == "null" {
		o.value = nil
		return nil
	}
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	o.value = &v
	return nil
}

func (o OptionalString) MarshalJSON() ([]byte, error) {
	if !o.set || o.value == nil {
		return []byte("null"), nil
	}
	return json.Marshal(*o.value)
}

func (o OptionalString) resolve(defaultValue string) (serverName string, sendSNI bool) {
	if !o.set {
		if defaultValue == "" {
			return "", false
		}
		if ip := net.ParseIP(defaultValue); ip != nil {
			return defaultValue, false
		}
		return defaultValue, true
	}
	if o.value == nil {
		return "", false
	}
	return *o.value, *o.value != ""
}

func (c *TLSConfig) UnmarshalYAML(value *yaml.Node) error {
	type rawTLSConfig struct {
		CertFile       string         `yaml:"cert_file,omitempty"`
		KeyFile        string         `yaml:"key_file,omitempty"`
		VerifyPeer     *bool          `yaml:"verify_peer,omitempty"`
		ReloadInterval string         `yaml:"reload_interval,omitempty"`
		CAFile         string         `yaml:"ca_file,omitempty"`
		ServerSNI      OptionalString `yaml:"server_sni,omitempty"`
	}
	var raw rawTLSConfig
	if err := value.Decode(&raw); err != nil {
		return err
	}
	c.CertFile = raw.CertFile
	c.KeyFile = raw.KeyFile
	c.ReloadInterval = raw.ReloadInterval
	c.CAFile = raw.CAFile
	c.ServerSNI = raw.ServerSNI
	c.verifyPeerSet = raw.VerifyPeer != nil
	if raw.VerifyPeer != nil {
		c.VerifyPeer = *raw.VerifyPeer
	} else {
		c.VerifyPeer = false
	}
	return nil
}

func (c TLSConfig) MarshalYAML() (any, error) {
	type rawTLSConfig struct {
		CertFile       string         `yaml:"cert_file,omitempty"`
		KeyFile        string         `yaml:"key_file,omitempty"`
		VerifyPeer     *bool          `yaml:"verify_peer,omitempty"`
		ReloadInterval string         `yaml:"reload_interval,omitempty"`
		CAFile         string         `yaml:"ca_file,omitempty"`
		ServerSNI      OptionalString `yaml:"server_sni,omitempty"`
	}
	raw := rawTLSConfig{
		CertFile:       c.CertFile,
		KeyFile:        c.KeyFile,
		ReloadInterval: c.ReloadInterval,
		CAFile:         c.CAFile,
		ServerSNI:      c.ServerSNI,
	}
	if c.verifyPeerSet {
		raw.VerifyPeer = &c.VerifyPeer
	}
	return raw, nil
}

func (c *TLSConfig) UnmarshalJSON(data []byte) error {
	type rawTLSConfig struct {
		CertFile       string         `json:"cert_file,omitempty"`
		KeyFile        string         `json:"key_file,omitempty"`
		VerifyPeer     *bool          `json:"verify_peer,omitempty"`
		ReloadInterval string         `json:"reload_interval,omitempty"`
		CAFile         string         `json:"ca_file,omitempty"`
		ServerSNI      OptionalString `json:"server_sni,omitempty"`
	}
	var raw rawTLSConfig
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	c.CertFile = raw.CertFile
	c.KeyFile = raw.KeyFile
	c.ReloadInterval = raw.ReloadInterval
	c.CAFile = raw.CAFile
	c.ServerSNI = raw.ServerSNI
	c.verifyPeerSet = raw.VerifyPeer != nil
	if raw.VerifyPeer != nil {
		c.VerifyPeer = *raw.VerifyPeer
	} else {
		c.VerifyPeer = false
	}
	return nil
}

func (c TLSConfig) MarshalJSON() ([]byte, error) {
	type rawTLSConfig struct {
		CertFile       string         `json:"cert_file,omitempty"`
		KeyFile        string         `json:"key_file,omitempty"`
		VerifyPeer     *bool          `json:"verify_peer,omitempty"`
		ReloadInterval string         `json:"reload_interval,omitempty"`
		CAFile         string         `json:"ca_file,omitempty"`
		ServerSNI      OptionalString `json:"server_sni,omitempty"`
	}
	raw := rawTLSConfig{
		CertFile:       c.CertFile,
		KeyFile:        c.KeyFile,
		ReloadInterval: c.ReloadInterval,
		CAFile:         c.CAFile,
		ServerSNI:      c.ServerSNI,
	}
	if c.verifyPeerSet {
		raw.VerifyPeer = &c.VerifyPeer
	}
	return json.Marshal(raw)
}

func (c TLSConfig) verifyPeerOr(defaultValue bool) bool {
	if c.verifyPeerSet {
		return c.VerifyPeer
	}
	return defaultValue
}

func (c TLSConfig) validateClientCertFiles() error {
	if c.CertFile == "" && c.KeyFile == "" {
		return nil
	}
	if c.CertFile == "" || c.KeyFile == "" {
		return fmt.Errorf("tls cert_file and key_file must both be set")
	}
	return nil
}
