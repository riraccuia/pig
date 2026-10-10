//go:build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import "golang.zx2c4.com/wireguard/conn"

func NewDefaultBind() conn.Bind { return NewStdNetBind() }
