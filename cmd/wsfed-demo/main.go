// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package main

import (
	"os"

	"github.com/rcbj/wsfed-caep-go/demo"
)

func main() {
	os.Exit(demo.Main(os.Args[1:]))
}
