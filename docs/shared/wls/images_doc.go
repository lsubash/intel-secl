/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package wls

import (
	"github.com/intel-secl/intel-secl/v5/pkg/model/wls"
)

// ImagesResponse response payload
// swagger:response ImagesResponse
type ImagesResponse struct {
	// in:body
	Body wls.ImagesResponse
}

// ImageInfo request payload
// swagger:parameters ImageInfo
type ImageInfo struct {
	// in:body
	Body wls.ImageInfo
}

// ImageFlavorCollection request payload
// swagger:parameters ImageFlavorCollection
type ImageFlavorCollection struct{
	// in:body
	Body wls.ImageFlavorCollection
}

// swagger:operation POST /images Images createImage
// ---
//
// description: |
//   Creates an association between the image and flavor(s) in the workload service database.
//   An image id from the image storage and flavor id(s) should be provided in the request body.
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
//     "$ref": "#/definitions/ImageInfo"
// responses:
//   '201':
//     description: Successfully created the association between specified image and flavor(s).
//     schema:
//       "$ref": "#/definitions/ImageInfo"
//
// x-sample-call-endpoint: https://wls.com:5000/wls/v2/images
// x-sample-call-input: |
//    {
//       "id" : "ffff021e-9669-4e53-9224-8880fb4e4081",
//       "flavor_ids" : [
//           "d6129610-4c8f-4ac4-8823-df4e925688c3",
//       ]
//    }
// x-sample-call-output: |
//    {
//       "id" : "ffff021e-9669-4e53-9224-8880fb4e4081",
//       "flavor_ids" : [
//           "d6129610-4c8f-4ac4-8823-df4e925688c3",
//       ]
//    }
// ---

// swagger:operation GET /images Images Search-Image
// ---
// description: |
//   Search(es) for the image(s) based on the provided filter criteria from the workload service database.
//   Minimum one query parameter should be provided to retrieve the images.
//   A valid bearer token should be provided to authorize this REST call.
//
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: flavor_id
//   description: Unique ID of the flavor.
//   in: query
//   type: string
//   format: uuid
// - name: image_id
//   description: Unique ID of the image.
//   in: query
//   type: string
//   format: uuid
// responses:
//   '200':
//     description: Successfully retrieved the images based on the provided filter criteria.
//     schema:
//       "$ref": "#/definitions/ImageFlavorCollection"
//
// x-sample-call-endpoint: https://wls.com:5000/wls/v2/images/image_id=ffff021e-9669-4e53-9224-8880fb4e4081
// x-sample-call-output: |
//    {
//        "imageFlavor": [
//            {
//                "id": "ffff021e-9669-4e53-9224-8880fb4e4081",
//                "flavor_ids": [
//                    "d6129610-4c8f-4ac4-8823-df4e925688c4"
//                ]
//            }
//        ]
//    }
// ---

// swagger:operation GET /images/{image_id} Images Retrieve-Image
// ---
// description: |
//   Retrieves the image details associated with a specified image id from the workload service
//   database. A valid bearer token should be provided to authorize this REST call.
//
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: image_id
//   description: Unique ID of the image.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '200':
//     description: Successfully retrieved the image for the specified image id.
//     schema:
//       "$ref": "#/definitions/ImageInfo"
//
// x-sample-call-endpoint: https://wls.com:5000/wls/v2/images/ffff021e-9669-4e53-9224-8880fb4e4081
// x-sample-call-output: |
//    {
//       "id": "ffff021e-9669-4e53-9224-8880fb4e4081",
//       "flavor_ids" : [
//           "d6129610-4c8f-4ac4-8823-df4e925688c3",
//        ]
//    }
// ---

// swagger:operation DELETE /images/{image_id} Images deleteImageById
// ---
// description: |
//   Deletes the image details associated with a specified image id in the workload service
//   database. A valid bearer token should be provided to authorize this REST call.
//
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: image_id
//   description: Unique ID of the image.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '204':
//     description: Successfully deleted the image.
//
// x-sample-call-endpoint: |
//    https://wls.com:5000/wls/v2/images/ffff021e-9669-4e53-9224-8880fb4e4081
// x-sample-call-output: |
//    204 No content
// ---

// swagger:operation PUT /images/{image_id}/flavors/{flavor_id} ImageFlavor addImageFlavor
// ---
// description: |
//   Assigns a flavor to the image associated with the specified image id in the workload service database.
//   A valid bearer token should be provided to authorize this REST call.
//
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: image_id
//   description: Unique ID of the image.
//   in: path
//   required: true
//   type: string
//   format: uuid
// - name: flavor_id
//   description: Unique ID of the flavor.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '201':
//     description: Successfully created a new flavor association with the specified image.
//
// x-sample-call-endpoint: |
//    https://wls.com:5000/wls/v2/images/ffff021e-9669-4e53-9224-8880fb4e4081/flavors/d6129610-4c8f-4ac4-8823-df4e925688c4
// x-sample-call-output: |
//    201 Created
// ---

// swagger:operation DELETE /images/{image_id}/flavors/{flavor_id} ImageFlavor deleteImageFlavorAssociation
// ---
// description: |
//   Removes the specified flavor associated with an image id from the workload service database.
//   A valid bearer token should be provided to authorize this REST call.
//
// security:
//  - bearerAuth: []
// parameters:
// - name: image_id
//   description: Unique ID of the image.
//   in: path
//   required: true
//   type: string
//   format: uuid
// - name: flavor_id
//   description: Unique ID of the flavor.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '204':
//     description: Successfully removed the specified flavor associated with the image.
//
// x-sample-call-endpoint: |
//    https://wls.com:5000/wls/v2/images/ffff021e-9669-4e53-9224-8880fb4e4081/flavors/d6129610-4c8f-4ac4-8823-df4e925688c4
// x-sample-call-output: |
//    204 No content
// ---

// swagger:operation GET /images/{image_id}/flavors/{flavor_id} ImageFlavor getImageFlavorByID
// ---
// description: |
//   Retrieves the specified flavor associated with an image id from the workload service database.
//   A valid bearer token should be provided to authorize this REST call.
//
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: image_id
//   description: Unique ID of the image.
//   in: path
//   required: true
//   type: string
//   format: uuid
// - name: flavor_id
//   description: Unique ID of the flavor.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '200':
//     description: Successfully retrieved the specified flavor associated with the image.
//     schema:
//      "$ref": "#/definitions/ImageInfo"
//
// x-sample-call-endpoint: |
//    https://wls.com:5000/wls/v2/images/ffff021e-9669-4e53-9224-8880fb4e4081/flavors/d6129610-4c8f-4ac4-8823-df4e925688c4
// x-sample-call-output: |
//    {
//       "id": "ffff021e-9669-4e53-9224-8880fb4e4081",
//       "flavor_ids" : [
//           "d6129610-4c8f-4ac4-8823-df4e925688c3",
//        ]
//    }
// ---

// swagger:operation GET /images/{image_id}/flavors ImageFlavor retrieveFlavorForImageId
// ---
// description: |
//   Retrieves the flavor containing the provided flavor part associated with a specified image from
//   the workload service database. The query parameter 'flavor_part' is mandatory.
//   A valid bearer token should be provided to authorize this REST call.
//
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: image_id
//   description: Unique ID of the image.
//   in: path
//   required: true
//   type: string
//   format: uuid
// - name: flavor_part
//   description: Flavor part string.
//   in: query
//   required: true
//   type: string
// responses:
//   '200':
//     description: Successfully retrieved the flavor containing the provided flavor part.
//     schema:
//      "$ref": "#/definitions/ImageInfo"
//
// x-sample-call-endpoint: |
//    https://wls.com:5000/wls/v2/images/ffff021e-9669-4e53-9224-8880fb4e4081/flavors
// x-sample-call-output: |
//    {
//       "id": "ffff021e-9669-4e53-9224-8880fb4e4081",
//       "flavor_ids" : [
//           "d6129610-4c8f-4ac4-8823-df4e925688c3",
//        ]
//    }
// ---

