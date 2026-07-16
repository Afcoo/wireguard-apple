//go:build !darwin

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Afcoo.
 */

package main

import "golang.zx2c4.com/wireguard/conn"

func newWireGuardBind() conn.Bind {
	return conn.NewStdNetBind()
}
