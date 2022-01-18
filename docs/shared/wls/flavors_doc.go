/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package wls

import (
	flvr "github.com/intel-secl/intel-secl/v5/pkg/lib/flavor"
)

// FlavorCreateInfo request payload
// swagger:parameters FlavorCreateInfo
type FlavorCreateInfo struct {
	// in:body
	Body flvr.SignedImageFlavor
}

// FlavorResponse response payload
// swagger:response FlavorResponse
type FlavorResponse struct {
	// in:body
	Body flvr.ImageFlavor
}

type FlavorsResponse []flvr.ImageFlavor

// FlavorsResponse response payload
// swagger:response FlavorsResponse
type SwaggFlavorsResponse struct {
	// in:body
	Body FlavorsResponse
}

// SignedFlavorCollection response payload
// swagger:response SignedFlavorCollection
type SignedFlavorCollection struct{
	// in:body
	Body flvr.SignedFlavorCollection
}

// swagger:operation POST /flavors Flavors createFlavor
// ---
//
// description: |
//   Creates a flavor for the encrypted image in the workload service database.
//   Flavor can be created by providing the image flavor content obtained from the WPM after encrypting the image.
//   A valid bearer token should be provided to authorize this REST call.
//
// security:
//  - bearerAuth: []
// consumes:
//  - application/json
// produces:
//  - application/json
// parameters:
// - name: request body
//   in: body
//   required: true
//   schema:
//     "$ref": "#/definitions/SignedImageFlavor"
// responses:
//   '201':
//     description: Successfully created the flavor.
//     schema:
//       "$ref": "#/definitions/ImageFlavor"
//
// x-sample-call-endpoint: https://wls.com:5000/wls/v2/flavors
// x-sample-call-input: |
//    {
//       "flavor": {
//          "meta": {
//             "id": "d6129610-4c8f-4ac4-8823-df4e925688c4",
//             "description": {
//                "flavor_part": "CONTAINER_IMAGE",
//                "label": "label_image-test-4"
//             }
//          },
//          "encryption_required": true,
//          "encryption": {
//             "key_url": "https://<kbsservice.example.com>:<kbs port>/v1/keys/60a9fe49-612f-4b66-bf86-b75c7873f3b3/transfer",
//             "digest": "3JiqO+O4JaL2qQxpzRhTHrsFpDGIUDV8fTWsXnjHVKY="
//          }
//       },
//       "signature": "CStRpWgj0De7+xoX1uFSOacLAZeEcodUuvH62B4hVoiIEriVaHxrLJhBjnIuSPmIoZewCdTShw7GxmMQiMik
//       CrVhaUilYk066TckOcLW/E3K+7NAiZ5kuS96J6dVxgJ+9k7iKf7Z+6lnWUJz92VWLP4U35WK4MtV+MPTYn2Zj1p+/tTUuSqlk8
//       KCmpywzI1J1/XXjvqee3M9cGInnbOUGEFoLBAO1+w30yptoNxKEaB/9t3qEYywk8buT5GEMYUjJEj9PGGaW+lR37x0zcXggwMg
//       /RsijMV6rNKsjjC0fN1vGswzoaIJPD1RJkQ8X9l3AaM0qhLBQDrurWxKK4KSQSpI0BziGPkKi5vAeeRkVfU5JXNdPxdOkyXVeb
//       eMQR9bYntXtZl41qjOZ0zIOKAHNJiBLyMYausbTZHVCwDuA/HBAT8i7JAIesxexX89bL+khPebHWkHaifS4NejymbGzM+n62EH
//       uoeIo33qDMQ/U0FA3i6gRy0s/sFQVXR0xk8l"
//    }
// x-sample-call-output: |
//  {
//    "flavor": {
//        "meta": {
//            "id": "d6129610-4c8f-4ac4-8823-df4e925688c4",
//            "description": {
//                "flavor_part": "CONTAINER_IMAGE",
//                "label": "label_image-test-4"
//            }
//        },
//        "encryption_required": true,
//        "encryption": {
//            "key_url": "https://<kbsservice.example.com>:<kbs port>/v1/keys/60a9fe49-612f-4b66-bf86-b75c7873f3b3/transfer",
//            "digest": "3JiqO+O4JaL2qQxpzRhTHrsFpDGIUDV8fTWsXnjHVKY="
//        },
//        "integrity_enforced": false
//    }
//  }
// ---

// swagger:operation DELETE /flavors/{flavor_id} Flavors deleteFlavorByID
// ---
// description: |
//   Deletes the flavor associated with a specified flavor id from the workload service
//   database. A valid bearer token should be provided to authorize this REST call.
//
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: flavor_id
//   description: Unique ID of the flavor.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '204':
//     description: Successfully deleted the flavor for the specified flavor id.
//
// x-sample-call-endpoint: |
//    https://wls.com:5000/wls/v2/flavors/d6129610-4c8f-4ac4-8823-df4e925688c4
// x-sample-call-output: |
//   204 No content
// ---

// swagger:operation GET /flavors/{flavor_id} Flavors getFlavorById
// ---
// description: |
//   Retrieves the flavor associated with a specified flavor ID from the workload service
//   database. The path parameter can be flavor ID
//   A valid bearer token should be provided to authorize this REST call.
//
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: flavor_id
//   description: Unique ID of the flavor.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '200':
//     description: Successfully retrieved the flavor for the specified flavor id
//     schema:
//       "$ref": "#/definitions/ImageFlavor"
//
// x-sample-call-endpoint: |
//    https://wls.com:5000/wls/v2/flavors/d6129610-4c8f-4ac4-8823-df4e925688c4
// x-sample-call-output: |
//  {
//    "flavor": {
//        "meta": {
//            "id": "d6129610-4c8f-4ac4-8823-df4e925688c4",
//            "description": {
//                "flavor_part": "CONTAINER_IMAGE",
//                "label": "label_image-test-4"
//            }
//        },
//        "encryption_required": true,
//        "encryption": {
//            "key_url": "https://<kbsservice.example.com>:<kbs port>/v1/keys/60a9fe49-612f-4b66-bf86-b75c7873f3b3/transfer",
//            "digest": "3JiqO+O4JaL2qQxpzRhTHrsFpDGIUDV8fTWsXnjHVKY="
//        },
//        "integrity_enforced": false
//    }
//  }
// ---

// swagger:operation GET /flavors Flavors Search-Flavors
// ---
// description: |
//   Retrieves the flavor associated with a specified flavor ID from the workload service
//   database. The path parameter can be flavor either flavor ID or flavor label
//   A valid bearer token should be provided to authorize this REST call.
//
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: id
//   description: Unique ID of the flavor.
//   in: query
//   required: false
//   type: string
//   format: uuid
// - name: label
//   description: flavor label.
//   in: query
//   required: false
//   type: string
// responses:
//   '200':
//     description: Successfully retrieved the flavor for the specified flavor id or flavor label.
//     schema:
//       "$ref": "#/definitions/SignedFlavorCollection"
//
// x-sample-call-endpoint: |
//    https://wls.com:5000/wls/v2/flavors?id=d6129610-4c8f-4ac4-8823-df4e925688c4
// x-sample-call-output: |
//  {
//    "flavor": {
//        "meta": {
//            "id": "d6129610-4c8f-4ac4-8823-df4e925688c4",
//            "description": {
//                "flavor_part": "CONTAINER_IMAGE",
//                "label": "label_image-test-4"
//            }
//        },
//        "encryption_required": true,
//        "encryption": {
//            "key_url": "https://<kbsservice.example.com>:<kbs port>/v1/keys/60a9fe49-612f-4b66-bf86-b75c7873f3b3/transfer",
//            "digest": "3JiqO+O4JaL2qQxpzRhTHrsFpDGIUDV8fTWsXnjHVKY="
//        },
//        "integrity_enforced": false
//    }
//  }
// ---
