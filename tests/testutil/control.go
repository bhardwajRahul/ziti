package testutil

import (
	"github.com/openziti/channel/v4"
	"github.com/openziti/ziti/common/handler_common"
	"github.com/openziti/ziti/common/pb/ctrl_pb"
	"github.com/stretchr/testify/require"
	"time"
)

func AcceptControl(id string, uf channel.UnderlayFactory, assertions *require.Assertions) (channel.Channel, *MessageCollector) {
	msgc := NewMessageCollector(id)
	bindHandler := func(binding channel.Binding) error {
		binding.AddReceiveHandler(channel.AnyContentType, msgc)
		binding.AddReceiveHandlerF(int32(ctrl_pb.ContentType_VerifyRouterType), func(msg *channel.Message, ch channel.Channel) {
			handler_common.SendSuccess(msg, ch, "link success")
		})
		return nil
	}

	timeoutUF := NewTimeoutUnderlayFactory(uf, 2*time.Second)
	ch, err := channel.NewChannel(id, timeoutUF, channel.BindHandlerF(bindHandler), channel.DefaultOptions())
	assertions.NoError(err)
	return ch, msgc
}
