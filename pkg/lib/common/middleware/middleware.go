/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package middleware

import "net/http"

// EndpointHandler which writes generic response
type EndpointHandler func(w http.ResponseWriter, r *http.Request) error
