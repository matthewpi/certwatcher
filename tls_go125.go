// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 Matthew Penner

//go:build !go1.26

package certwatcher

import "crypto/tls"

var defaultCurvePreferences = []tls.CurveID{
	tls.X25519MLKEM768,
	tls.CurveP256,
	tls.CurveP384,
	tls.CurveP521,
}
