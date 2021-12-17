// Workload Service
//
// Workload Service resources are used to manage images, flavors and reports.
// Workload Service handles the mapping of the image ID to the appropriate key ID in the form of Flavors.
// When the encrypted image is used to launch new VM or container, WLA will request the decryption key from the Workload Service.
// Then Workload Service will initiate the key transfer request to the Key Broker.
//
//  License: Copyright (C) 2021 Intel Corporation. SPDX-License-Identifier: BSD-3-Clause
//
//  Version: 2.2
//  Host: wls.com:5000
//  BasePath: /wls/v2
//
//  Schemes: https
//
//  SecurityDefinitions:
//   bearerAuth:
//     type: apiKey
//     in: header
//     name: Authorization
//     description: Enter your bearer token in the format **Bearer &lt;token&gt;**
//
// swagger:meta
package wls
