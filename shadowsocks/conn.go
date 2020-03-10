package shadowsocks

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

const (
	AddrMask        byte = 0xf
)

// 加密连接
type Conn struct {
	net.Conn 		//原始连接
	*Cipher			//加密器
	readBuf  []byte	//读缓冲
	writeBuf []byte //写缓冲
}

func NewConn(c net.Conn, cipher *Cipher) *Conn {
	return &Conn{
		Conn:     c,
		Cipher:   cipher,
		readBuf:  leakyBuf.Get(),
		writeBuf: leakyBuf.Get()}
}

func (c *Conn) Close() error {
	leakyBuf.Put(c.readBuf)
	leakyBuf.Put(c.writeBuf)
	return c.Conn.Close()
}

// 字符串类型的地址信息转换成rawaddr
// host 作为域名类型来传递
func RawAddr(addr string) (buf []byte, err error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("shadowsocks: address error %s %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("shadowsocks: invalid port %s", addr)
	}

	// 获取host长度
	hostLen := len(host)

	// 计算总长度
	l := 1 + 1 + hostLen + 2 // addrType + lenByte + address + port
	buf = make([]byte, l)
	buf[0] = 3             // 3 means the address is domain name
	buf[1] = byte(hostLen) // host address length  followed by host address
	copy(buf[2:], host)
	binary.BigEndian.PutUint16(buf[2+hostLen:2+hostLen+2], uint16(port))
	return
}

// DialWithRawAddr is intended for use by users implementing a local socks proxy.
// rawaddr shoud contain part of the data in socks request, starting from the
// ATYP field. (Refer to rfc1928 for more information.)
func DialWithRawAddr(rawaddr []byte, server string, cipher *Cipher) (c *Conn, err error) {
	// ss-local -> ss-remote 原始conn
	conn, err := net.Dial("tcp", server)
	if err != nil {
		return
	}

	// ss-local -> ss-remote 加密conn
	c = NewConn(conn, cipher)
	if _, err = c.Write(rawaddr); err != nil {
		c.Close()
		return nil, err
	}
	return
}

// Dial: addr should be in the form of host:port
func Dial(addr, server string, cipher *Cipher) (c *Conn, err error) {
	ra, err := RawAddr(addr)
	if err != nil {
		return
	}
	return DialWithRawAddr(ra, server, cipher)
}

// 加密连接的读方法，读取到的数据b是已经解密好了的数据
// 1. 通过原始连接读取到Conn内部缓冲
// 2. 解密，并把解密后的数据放入到b中
func (c *Conn) Read(b []byte) (n int, err error) {
	// 解密流
	if c.dec == nil {
		// 初始化解密器
		// initialization vector
		iv := make([]byte, c.info.ivLen)
		// 读取初始向量
		if _, err = io.ReadFull(c.Conn, iv); err != nil {
			return
		}
		//构造解密流
		if err = c.initDecrypt(iv); err != nil {
			return
		}
	}

	// b 决定了读取多少个字节
	cipherData := c.readBuf
	if len(b) > len(cipherData) {
		cipherData = make([]byte, len(b))
	} else {
		cipherData = cipherData[:len(b)]
	}

	// 先读取到缓冲
	n, err = c.Conn.Read(cipherData)
	if n > 0 {
		// 解密，并把解密后的数据放入到b中
		c.decrypt(b[0:n], cipherData[0:n])
	}
	return
}

// 加密连接的写方法
// ****** 每个连接一个iv，同一个连接iv相同
// 1. 加密明文b，并写入到Conn内部缓冲
// 2. 通过原始连接写入密文
func (c *Conn) Write(b []byte) (n int, err error) {
	var iv []byte
	if c.enc == nil {
		// 初始化加密器
		iv, err = c.initEncrypt()
		if err != nil {
			return
		}
	}

	cipherData := c.writeBuf
	// 加密后的数据为：iv + 密文
	dataSize := len(b) + len(iv)
	if dataSize > len(cipherData) {
		cipherData = make([]byte, dataSize)
	} else {
		cipherData = cipherData[:dataSize]
	}

	if iv != nil {
		// Put initialization vector in buffer, do a single write to send both
		// iv and data.
		copy(cipherData, iv)
	}

	// 加密
	c.encrypt(cipherData[len(iv):], b)
	n, err = c.Conn.Write(cipherData)
	return
}
