// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package main

import (
	"os"

	"github.com/rcbj/wsfed-caep-go/wsfed"
)

func main() {
	os.Exit(wsfed.Main(os.Args[1:], os.Stdout))
}
