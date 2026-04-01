package cloudflared

import (
	"io"
	"net"
	"time"

	E "github.com/sagernet/sing/common/exceptions"

	"github.com/sagernet/ws"
	"github.com/sagernet/ws/wsutil"
)

const closeWriteTimeout = 5 * time.Second

type websocketConn struct {
	net.Conn
	reader         *wsutil.Reader
	controlHandler wsutil.FrameHandlerFunc
}

func newWebsocketConn(conn net.Conn, state ws.State) *websocketConn {
	controlHandler := wsutil.ControlFrameHandler(conn, state)
	return &websocketConn{
		Conn: conn,
		reader: &wsutil.Reader{
			Source:         conn,
			State:          state,
			OnIntermediate: controlHandler,
		},
		controlHandler: controlHandler,
	}
}

func (c *websocketConn) Read(p []byte) (int, error) {
	for {
		n, err := c.reader.Read(p)
		if n > 0 {
			return n, nil
		}
		if !isRetryableReadError(err) {
			return 0, wrapWebsocketError(err)
		}
		header, err := c.reader.NextFrame()
		if err != nil {
			return 0, wrapWebsocketError(err)
		}
		if header.OpCode.IsControl() {
			if header.Length > 128 {
				return 0, wsutil.ErrFrameTooLarge
			}
			err = c.controlHandler(header, c.reader)
			if err != nil {
				return 0, wrapWebsocketError(err)
			}
			continue
		}
		if header.OpCode&ws.OpBinary == 0 {
			err = c.reader.Discard()
			if err != nil {
				return 0, wrapWebsocketError(err)
			}
			continue
		}
	}
}

func (c *websocketConn) Write(p []byte) (int, error) {
	err := wsutil.WriteServerBinary(c.Conn, p)
	if err != nil {
		return 0, wrapWebsocketError(err)
	}
	return len(p), nil
}

func (c *websocketConn) Close() error {
	c.Conn.SetWriteDeadline(time.Now().Add(closeWriteTimeout))
	frame := ws.NewCloseFrame(ws.NewCloseFrameBody(
		ws.StatusNormalClosure, "",
	))
	ws.WriteFrame(c.Conn, frame)
	return c.Conn.Close()
}

func isRetryableReadError(err error) bool {
	return E.IsMulti(err, io.EOF, wsutil.ErrNoFrameAdvance)
}

func wrapWebsocketError(err error) error {
	if err == nil {
		return nil
	}
	closedErr, isClosedErr := E.Cast[wsutil.ClosedError](err)
	if isClosedErr {
		if closedErr.Code == ws.StatusNormalClosure || closedErr.Code == ws.StatusNoStatusRcvd {
			return io.EOF
		}
	}
	return err
}
