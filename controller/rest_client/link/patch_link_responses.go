// Code generated by go-swagger; DO NOT EDIT.

//
// Copyright NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// __          __              _
// \ \        / /             (_)
//  \ \  /\  / /_ _ _ __ _ __  _ _ __   __ _
//   \ \/  \/ / _` | '__| '_ \| | '_ \ / _` |
//    \  /\  / (_| | |  | | | | | | | | (_| | : This file is generated, do not edit it.
//     \/  \/ \__,_|_|  |_| |_|_|_| |_|\__, |
//                                      __/ |
//                                     |___/

package link

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/openziti/ziti/controller/rest_model"
)

// PatchLinkReader is a Reader for the PatchLink structure.
type PatchLinkReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PatchLinkReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPatchLinkOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPatchLinkBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPatchLinkUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewPatchLinkNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewPatchLinkTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 503:
		result := NewPatchLinkServiceUnavailable()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewPatchLinkOK creates a PatchLinkOK with default headers values
func NewPatchLinkOK() *PatchLinkOK {
	return &PatchLinkOK{}
}

/* PatchLinkOK describes a response with status code 200, with default header values.

The patch request was successful and the resource has been altered
*/
type PatchLinkOK struct {
	Payload *rest_model.Empty
}

func (o *PatchLinkOK) Error() string {
	return fmt.Sprintf("[PATCH /links/{id}][%d] patchLinkOK  %+v", 200, o.Payload)
}
func (o *PatchLinkOK) GetPayload() *rest_model.Empty {
	return o.Payload
}

func (o *PatchLinkOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.Empty)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchLinkBadRequest creates a PatchLinkBadRequest with default headers values
func NewPatchLinkBadRequest() *PatchLinkBadRequest {
	return &PatchLinkBadRequest{}
}

/* PatchLinkBadRequest describes a response with status code 400, with default header values.

The supplied request contains invalid fields or could not be parsed (json and non-json bodies). The error's code, message, and cause fields can be inspected for further information
*/
type PatchLinkBadRequest struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *PatchLinkBadRequest) Error() string {
	return fmt.Sprintf("[PATCH /links/{id}][%d] patchLinkBadRequest  %+v", 400, o.Payload)
}
func (o *PatchLinkBadRequest) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *PatchLinkBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchLinkUnauthorized creates a PatchLinkUnauthorized with default headers values
func NewPatchLinkUnauthorized() *PatchLinkUnauthorized {
	return &PatchLinkUnauthorized{}
}

/* PatchLinkUnauthorized describes a response with status code 401, with default header values.

The currently supplied session does not have the correct access rights to request this resource
*/
type PatchLinkUnauthorized struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *PatchLinkUnauthorized) Error() string {
	return fmt.Sprintf("[PATCH /links/{id}][%d] patchLinkUnauthorized  %+v", 401, o.Payload)
}
func (o *PatchLinkUnauthorized) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *PatchLinkUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchLinkNotFound creates a PatchLinkNotFound with default headers values
func NewPatchLinkNotFound() *PatchLinkNotFound {
	return &PatchLinkNotFound{}
}

/* PatchLinkNotFound describes a response with status code 404, with default header values.

The requested resource does not exist
*/
type PatchLinkNotFound struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *PatchLinkNotFound) Error() string {
	return fmt.Sprintf("[PATCH /links/{id}][%d] patchLinkNotFound  %+v", 404, o.Payload)
}
func (o *PatchLinkNotFound) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *PatchLinkNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchLinkTooManyRequests creates a PatchLinkTooManyRequests with default headers values
func NewPatchLinkTooManyRequests() *PatchLinkTooManyRequests {
	return &PatchLinkTooManyRequests{}
}

/* PatchLinkTooManyRequests describes a response with status code 429, with default header values.

The resource requested is rate limited and the rate limit has been exceeded
*/
type PatchLinkTooManyRequests struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *PatchLinkTooManyRequests) Error() string {
	return fmt.Sprintf("[PATCH /links/{id}][%d] patchLinkTooManyRequests  %+v", 429, o.Payload)
}
func (o *PatchLinkTooManyRequests) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *PatchLinkTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchLinkServiceUnavailable creates a PatchLinkServiceUnavailable with default headers values
func NewPatchLinkServiceUnavailable() *PatchLinkServiceUnavailable {
	return &PatchLinkServiceUnavailable{}
}

/* PatchLinkServiceUnavailable describes a response with status code 503, with default header values.

The request could not be completed due to the server being busy or in a temporarily bad state
*/
type PatchLinkServiceUnavailable struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *PatchLinkServiceUnavailable) Error() string {
	return fmt.Sprintf("[PATCH /links/{id}][%d] patchLinkServiceUnavailable  %+v", 503, o.Payload)
}
func (o *PatchLinkServiceUnavailable) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *PatchLinkServiceUnavailable) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
