/*
	Copyright NetFoundry Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package handler_edge_ctrl

import (
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/channel/v4"
	"github.com/openziti/ziti/common/pb/edge_ctrl_pb"
	"github.com/openziti/ziti/controller/env"
	"google.golang.org/protobuf/proto"
)

type resyncHandler struct {
	appEnv   *env.AppEnv
	callback func(routerId string, respHello *edge_ctrl_pb.RequestClientReSync)
}

func NewResyncHandler(appEnv *env.AppEnv, callback func(routerId string, respHello *edge_ctrl_pb.RequestClientReSync)) *resyncHandler {
	return &resyncHandler{
		appEnv:   appEnv,
		callback: callback,
	}
}

func (h *resyncHandler) ContentType() int32 {
	return env.RequestClientReSyncType
}

func (h *resyncHandler) HandleReceive(msg *channel.Message, ch channel.Channel) {
	resyncReq := &edge_ctrl_pb.RequestClientReSync{}
	if err := proto.Unmarshal(msg.Body, resyncReq); err != nil {
		pfxlog.Logger().WithError(err).Error("could not unmarshal RequestClientReSync")
		return
	}

	h.callback(ch.Id(), resyncReq)
}
