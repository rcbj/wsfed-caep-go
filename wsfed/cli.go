// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package wsfed

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const usageText = `Usage:
  wsfed-caep generate-keys --config <wsfed.json> [--cn <name>] [--days <n>] [--bits <n>] [--force]
  wsfed-caep generate-keys --key <file> --cert <file> [--cn <name>] [--days <n>] [--bits <n>] [--force]
      A new RSA key and a self-signed certificate, written where the configuration's privateKey and
      certificate point (or to --key and --cert). Refuses to replace existing files without --force.
      The key decrypts encrypted assertions and can authenticate the Shared Signals receiver (mutual
      TLS); WS-Federation itself signs nothing. The common name defaults to one naming the realm.

  wsfed-caep metadata --config <wsfed.json> [--out <file>]
      This relying party's federation metadata, from the configuration (and its certificate, when it
      has one): give it to the identity provider. Written to --out, or to standard output.`

func parseCLI(argv []string) (string, map[string]string, error) {
	if len(argv) == 0 {
		return "", map[string]string{}, nil
	}
	command, rest := argv[0], argv[1:]
	args := map[string]string{}
	for i := 0; i < len(rest); i++ {
		item := rest[i]
		if !strings.HasPrefix(item, "--") {
			return "", nil, fmt.Errorf("unexpected argument %s\n\n%s", item, usageText)
		}
		key := item[2:]
		if key == "force" || key == "help" {
			args[key] = "true"
			continue
		}
		if i+1 >= len(rest) || strings.HasPrefix(rest[i+1], "--") {
			return "", nil, fmt.Errorf("--%s needs a value\n\n%s", key, usageText)
		}
		args[key] = rest[i+1]
		i++
	}
	return command, args, nil
}

func stripFile(value string) string {
	if strings.HasPrefix(value, "file:") {
		return value[5:]
	}
	return value
}

func keyPaths(args map[string]string) (string, string, string, error) {
	configPath := args["config"]
	key := args["key"]
	cert := args["cert"]
	commonName := args["cn"]
	if configPath != "" {
		rawBytes, err := os.ReadFile(configPath)
		if err != nil {
			return "", "", "", err
		}
		var raw map[string]any
		if err := json.Unmarshal(rawBytes, &raw); err != nil {
			return "", "", "", err
		}
		base, err := filepath.Abs(configPath)
		if err != nil {
			base = configPath
		}
		base = filepath.Dir(base)
		at := func(value, what string) (string, error) {
			if value == "" || strings.Contains(value, "-----BEGIN ") {
				return "", fmt.Errorf("%s's %s must be a file path for generate-keys to write to", configPath, what)
			}
			value = stripFile(value)
			if filepath.IsAbs(value) {
				return value, nil
			}
			return filepath.Join(base, value), nil
		}
		if key == "" {
			if text, ok := raw["privateKey"].(string); ok && text != "" {
				key, err = at(text, "privateKey")
				if err != nil {
					return "", "", "", err
				}
			}
		}
		if cert == "" {
			if text, ok := raw["certificate"].(string); ok && text != "" {
				cert, err = at(text, "certificate")
				if err != nil {
					return "", "", "", err
				}
			}
		}
		if commonName == "" {
			if realm, ok := raw["realm"].(string); ok && realm != "" {
				commonName = clipRunes("wsfed-caep-nodejs relying party "+realm, 64)
			}
		}
	}
	if key == "" || cert == "" {
		return "", "", "", fmt.Errorf("generate-keys needs --config, or --key and --cert\n\n%s", usageText)
	}
	key, _ = filepath.Abs(key)
	cert, _ = filepath.Abs(cert)
	if commonName == "" {
		commonName = "wsfed-caep-nodejs relying party"
	}
	return key, cert, commonName, nil
}

func clipRunes(value string, n int) string {
	r := []rune(value)
	if len(r) > n {
		return string(r[:n])
	}
	return value
}

// Main runs generate-keys and metadata. It writes to out and returns a process status.
func Main(argv []string, out io.Writer) int {
	if out == nil {
		out = os.Stdout
	}
	command, args, err := parseCLI(argv)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 1
	}
	if command == "" || args["help"] == "true" || command == "help" {
		fmt.Fprintln(out, usageText)
		return 0
	}
	if command == "generate-keys" {
		key, cert, commonName, err := keyPaths(args)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return 1
		}
		if args["force"] != "true" && (exists(key) || exists(cert)) {
			which := key
			if !exists(key) {
				which = cert
			}
			fmt.Fprintf(os.Stderr, "%s already exists; pass --force to replace the key pair.\nReplacing it means giving the identity provider the new metadata before it next encrypts to this relying party.\n", which)
			return 1
		}
		days := 1095
		bits := 3072
		if text, ok := args["days"]; ok {
			days, err = strconv.Atoi(text)
			if err != nil || days <= 0 {
				fmt.Fprintln(os.Stderr, "--days must be a positive whole number")
				return 1
			}
		}
		if text, ok := args["bits"]; ok {
			bits, err = strconv.Atoi(text)
			if err != nil || (bits != 2048 && bits != 3072 && bits != 4096) {
				fmt.Fprintln(os.Stderr, "--bits must be 2048, 3072 or 4096")
				return 1
			}
		}
		pair, err := CreateSelfSignedKeyPair(commonName, days, bits)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return 1
		}
		if err := os.MkdirAll(filepath.Dir(key), 0o755); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return 1
		}
		if err := os.MkdirAll(filepath.Dir(cert), 0o755); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return 1
		}
		if err := os.WriteFile(key, []byte(pair.PrivateKeyPEM), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return 1
		}
		if err := os.WriteFile(cert, []byte(pair.CertificatePEM), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return 1
		}
		fmt.Fprintf(out, "Wrote the private key  %s (mode 600)\n", key)
		fmt.Fprintf(out, "Wrote the certificate  %s\n", cert)
		fmt.Fprintf(out, "  subject   %s\n", pair.Certificate.Subject.String())
		return 0
	}
	if command == "metadata" {
		configPath := args["config"]
		if configPath == "" {
			fmt.Fprintf(os.Stderr, "metadata needs --config\n\n%s\n", usageText)
			return 1
		}
		rawBytes, err := os.ReadFile(configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return 1
		}
		var raw map[string]any
		if err := json.Unmarshal(rawBytes, &raw); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return 1
		}
		delete(raw, "idpCa")
		base := filepath.Dir(configPath)
		if abs, err := filepath.Abs(configPath); err == nil {
			base = filepath.Dir(abs)
		}
		party, err := Create(raw, base)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return 1
		}
		xml := party.Metadata()
		if target := args["out"]; target != "" {
			path, _ := filepath.Abs(target)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
				return 1
			}
			if err := os.WriteFile(path, []byte(xml), 0o644); err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
				return 1
			}
			fmt.Fprintf(out, "Wrote the relying party metadata to %s\n", path)
		} else {
			fmt.Fprint(out, xml)
		}
		return 0
	}
	fmt.Fprintf(os.Stderr, "unknown command %s\n\n%s\n", command, usageText)
	return 1
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
