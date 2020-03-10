package shadowsocks

import (
	"fmt"
	"net"
	"time"
)

const (
	maxPacketSize = 4096 // increase it if error occurs
)

var (
	errPacketTooSmall  = fmt.Errorf("[udp]read error: cannot decrypt, received packet is smaller than ivLen")
	errPacketTooLarge  = fmt.Errorf("[udp]read error: received packet is latger than maxPacketSize(%d)", maxPacketSize)
	errBufferTooSmall  = fmt.Errorf("[udp]read error: given buffer is too small to hold data")
)

type SecurePacketConn struct {
	net.PacketConn
	*Cipher
}

func NewSecurePacketConn(c net.PacketConn, cipher *Cipher) *SecurePacketConn {
	return &SecurePacketConn{
		PacketConn: c,
		Cipher:     cipher,
	}
}

func (c *SecurePacketConn) Close() error {
	return c.PacketConn.Close()
}

/**
 作用：从原始连接读取数据
 步骤：
 1. 从原始连接读取数据（密文）
 2. 解密并返回给b
 */
func (c *SecurePacketConn) ReadFrom(b []byte) (n int, src net.Addr, err error) {
	cipher := c.Copy()
	// 临时缓存
	buf := make([]byte, 4096)
	n, src, err = c.PacketConn.ReadFrom(buf)
	if err != nil {
		return
	}

	// 读取到的包比iv还短
	if n < c.info.ivLen {
		return 0, nil, errPacketTooSmall
	}

	// 读取到的密文比b大
	if len(b) < n-c.info.ivLen {
		err = errBufferTooSmall // just a warning
	}

	// 密文的格式：iv|密文，读取iv
	iv := make([]byte, c.info.ivLen)
	copy(iv, buf[:c.info.ivLen])

	// 通过iv生成解密器
	if err = cipher.initDecrypt(iv); err != nil {
		return
	}

	// 解密
	cipher.decrypt(b[0:], buf[c.info.ivLen:n])
	n -= c.info.ivLen

	return
}

/**
作用：把明文加密后写入到原始连接
步骤：
1. 加密
2. 把密文写入原始连接
*/
func (c *SecurePacketConn) WriteTo(b []byte, dst net.Addr) (n int, err error) {
	cipher := c.Copy()

	// 初始化加密器并返回iv
	iv, err := cipher.initEncrypt()
	if err != nil {
		return
	}

	// 数据包：iv|密文， b是待写入的明文
	packetLen := len(b) + len(iv)

	cipherData := make([]byte, packetLen)
	// iv放到最前面
	copy(cipherData, iv)

	// 加密数据放到iv后面
	cipher.encrypt(cipherData[len(iv):], b)

	// 把加密后的数据写入到原始连接
	n, err = c.PacketConn.WriteTo(cipherData, dst)
	return
}

func (c *SecurePacketConn) LocalAddr() net.Addr {
	return c.PacketConn.LocalAddr()
}

func (c *SecurePacketConn) SetDeadline(t time.Time) error {
	return c.PacketConn.SetDeadline(t)
}

func (c *SecurePacketConn) SetReadDeadline(t time.Time) error {
	return c.PacketConn.SetReadDeadline(t)
}

func (c *SecurePacketConn) SetWriteDeadline(t time.Time) error {
	return c.PacketConn.SetWriteDeadline(t)
}
