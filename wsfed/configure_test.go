// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package wsfed_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigureSignalsBehavior(t *testing.T) {
	root := filepath.Join("..")
	script := filepath.Join(root, "scripts", "configure_iya_sts.py")
	if _, err := os.Stat(script); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	base := `{
  "realm": "http://localhost:3000/",
  "replyUrl": "http://localhost:3000/wsfed",
  "privateKey": "generated/rp.key",
  "certificate": "generated/rp.crt",
  "idpMetadata": "generated/idp-metadata.xml",
  "idpCa": "generated/idp-ca.pem"
}`
	config := write("wsfed.json", base)
	withSSF := write("wsfed-ssf.json", strings.Replace(base, "\n}", ",\n  \"ssf\": {\"transmitter\": \"https://localhost:8081\"}\n}", 1))
	off := write("off.json", strings.Replace(base, "\n}", ",\n  \"signals\": false,\n  \"ssf\": {\"transmitter\": \"https://localhost:8081\"}\n}", 1))
	on := write("on.json", strings.Replace(base, "\n}", ",\n  \"signals\": true,\n  \"ssf\": {\"transmitter\": \"https://localhost:8081\"}\n}", 1))
	bad := write("bad.json", strings.Replace(base, "\n}", ",\n  \"signals\": \"no\"\n}", 1))
	code := `
import json, sys
sys.path.insert(0, sys.argv[1])
from configure_iya_sts import files_of, plan_for
base, with_ssf, off, on, bad = sys.argv[2:]
files = files_of(base)
ssf = files_of(with_ssf)
assert any(call["path"].endswith("/applications/add-certificate") for call in plan_for(ssf, "https://localhost:8081", ""))
assert not any(call["path"].endswith("/applications/add-certificate") for call in plan_for(files, "https://localhost:8081", ""))
off_files = files_of(off)
assert off_files["signals"] is False
assert off_files["ssf_transmitter"] == "https://localhost:8081"
assert off_files["realm"] == "http://localhost:3000/"
assert off_files["reply_url"] == "http://localhost:3000/wsfed"
assert not any(call["path"].endswith("/applications/add-certificate") for call in plan_for(off_files, "https://localhost:8081", ""))
assert not any(call["path"].endswith("/roles/add-member") for call in plan_for(off_files, "https://localhost:8081", ""))
assert "signals" not in files_of(on)
assert any(call["path"].endswith("/applications/add-certificate") for call in plan_for(files_of(on), "https://localhost:8081", ""))
try:
    files_of(bad)
except ValueError as err:
    assert str(err) == "signals must be true or false", str(err)
else:
    raise SystemExit("signals string was accepted")
print("ok")
`
	cmd := exec.Command("python3", "-c", code, filepath.Dir(script), config, withSSF, off, on, bad)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(string(out), "ok") {
		t.Fatal(string(out))
	}
}
