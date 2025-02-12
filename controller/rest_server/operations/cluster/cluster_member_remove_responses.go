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

package cluster

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/openziti/ziti/controller/rest_model"
)

// ClusterMemberRemoveOKCode is the HTTP code returned for type ClusterMemberRemoveOK
const ClusterMemberRemoveOKCode int = 200

/*ClusterMemberRemoveOK Base empty response

swagger:response clusterMemberRemoveOK
*/
type ClusterMemberRemoveOK struct {

	/*
	  In: Body
	*/
	Payload *rest_model.Empty `json:"body,omitempty"`
}

// NewClusterMemberRemoveOK creates ClusterMemberRemoveOK with default headers values
func NewClusterMemberRemoveOK() *ClusterMemberRemoveOK {

	return &ClusterMemberRemoveOK{}
}

// WithPayload adds the payload to the cluster member remove o k response
func (o *ClusterMemberRemoveOK) WithPayload(payload *rest_model.Empty) *ClusterMemberRemoveOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the cluster member remove o k response
func (o *ClusterMemberRemoveOK) SetPayload(payload *rest_model.Empty) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ClusterMemberRemoveOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// ClusterMemberRemoveBadRequestCode is the HTTP code returned for type ClusterMemberRemoveBadRequest
const ClusterMemberRemoveBadRequestCode int = 400

/*ClusterMemberRemoveBadRequest The supplied request contains invalid fields or could not be parsed (json and non-json bodies). The error's code, message, and cause fields can be inspected for further information

swagger:response clusterMemberRemoveBadRequest
*/
type ClusterMemberRemoveBadRequest struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewClusterMemberRemoveBadRequest creates ClusterMemberRemoveBadRequest with default headers values
func NewClusterMemberRemoveBadRequest() *ClusterMemberRemoveBadRequest {

	return &ClusterMemberRemoveBadRequest{}
}

// WithPayload adds the payload to the cluster member remove bad request response
func (o *ClusterMemberRemoveBadRequest) WithPayload(payload *rest_model.APIErrorEnvelope) *ClusterMemberRemoveBadRequest {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the cluster member remove bad request response
func (o *ClusterMemberRemoveBadRequest) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ClusterMemberRemoveBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(400)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// ClusterMemberRemoveUnauthorizedCode is the HTTP code returned for type ClusterMemberRemoveUnauthorized
const ClusterMemberRemoveUnauthorizedCode int = 401

/*ClusterMemberRemoveUnauthorized The currently supplied session does not have the correct access rights to request this resource

swagger:response clusterMemberRemoveUnauthorized
*/
type ClusterMemberRemoveUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewClusterMemberRemoveUnauthorized creates ClusterMemberRemoveUnauthorized with default headers values
func NewClusterMemberRemoveUnauthorized() *ClusterMemberRemoveUnauthorized {

	return &ClusterMemberRemoveUnauthorized{}
}

// WithPayload adds the payload to the cluster member remove unauthorized response
func (o *ClusterMemberRemoveUnauthorized) WithPayload(payload *rest_model.APIErrorEnvelope) *ClusterMemberRemoveUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the cluster member remove unauthorized response
func (o *ClusterMemberRemoveUnauthorized) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ClusterMemberRemoveUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// ClusterMemberRemoveNotFoundCode is the HTTP code returned for type ClusterMemberRemoveNotFound
const ClusterMemberRemoveNotFoundCode int = 404

/*ClusterMemberRemoveNotFound The requested resource does not exist

swagger:response clusterMemberRemoveNotFound
*/
type ClusterMemberRemoveNotFound struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewClusterMemberRemoveNotFound creates ClusterMemberRemoveNotFound with default headers values
func NewClusterMemberRemoveNotFound() *ClusterMemberRemoveNotFound {

	return &ClusterMemberRemoveNotFound{}
}

// WithPayload adds the payload to the cluster member remove not found response
func (o *ClusterMemberRemoveNotFound) WithPayload(payload *rest_model.APIErrorEnvelope) *ClusterMemberRemoveNotFound {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the cluster member remove not found response
func (o *ClusterMemberRemoveNotFound) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ClusterMemberRemoveNotFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(404)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// ClusterMemberRemoveTooManyRequestsCode is the HTTP code returned for type ClusterMemberRemoveTooManyRequests
const ClusterMemberRemoveTooManyRequestsCode int = 429

/*ClusterMemberRemoveTooManyRequests The resource requested is rate limited and the rate limit has been exceeded

swagger:response clusterMemberRemoveTooManyRequests
*/
type ClusterMemberRemoveTooManyRequests struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewClusterMemberRemoveTooManyRequests creates ClusterMemberRemoveTooManyRequests with default headers values
func NewClusterMemberRemoveTooManyRequests() *ClusterMemberRemoveTooManyRequests {

	return &ClusterMemberRemoveTooManyRequests{}
}

// WithPayload adds the payload to the cluster member remove too many requests response
func (o *ClusterMemberRemoveTooManyRequests) WithPayload(payload *rest_model.APIErrorEnvelope) *ClusterMemberRemoveTooManyRequests {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the cluster member remove too many requests response
func (o *ClusterMemberRemoveTooManyRequests) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ClusterMemberRemoveTooManyRequests) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(429)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// ClusterMemberRemoveServiceUnavailableCode is the HTTP code returned for type ClusterMemberRemoveServiceUnavailable
const ClusterMemberRemoveServiceUnavailableCode int = 503

/*ClusterMemberRemoveServiceUnavailable The request could not be completed due to the server being busy or in a temporarily bad state

swagger:response clusterMemberRemoveServiceUnavailable
*/
type ClusterMemberRemoveServiceUnavailable struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewClusterMemberRemoveServiceUnavailable creates ClusterMemberRemoveServiceUnavailable with default headers values
func NewClusterMemberRemoveServiceUnavailable() *ClusterMemberRemoveServiceUnavailable {

	return &ClusterMemberRemoveServiceUnavailable{}
}

// WithPayload adds the payload to the cluster member remove service unavailable response
func (o *ClusterMemberRemoveServiceUnavailable) WithPayload(payload *rest_model.APIErrorEnvelope) *ClusterMemberRemoveServiceUnavailable {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the cluster member remove service unavailable response
func (o *ClusterMemberRemoveServiceUnavailable) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ClusterMemberRemoveServiceUnavailable) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(503)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
