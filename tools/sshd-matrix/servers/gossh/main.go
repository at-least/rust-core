// A minimal SSH server on golang.org/x/crypto/ssh, exercising the app
// against a non-OpenSSH stack (the one behind Gitea/gliderlabs/bespoke
// bastions). Supports password (pwuser/conch-pw-1, bothuser/conch-pw-2) and
// public key (bothuser=keyA) auth, "session" channels with exec + pty +
// shell, and direct-tcpip (local port forwarding). Host key: an ed25519 key
// loaded from /keys/gossh_host or generated on first boot.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"

	"github.com/pkg/sftp"

	"golang.org/x/crypto/ssh"
)

func hostSigner() ssh.Signer {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		panic(err)
	}
	return s
}

func authorizedKey(path string) map[string]bool {
	out := map[string]bool{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for len(b) > 0 {
		pk, _, _, rest, err := ssh.ParseAuthorizedKey(b)
		if err != nil {
			break
		}
		out[string(pk.Marshal())] = true
		b = rest
	}
	return out
}

func main() {
	keyA := authorizedKey("/keys/keyA.pub")
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "pwuser" && string(pass) == "conch-pw-1" {
				return &ssh.Permissions{}, nil
			}
			if c.User() == "bothuser" && string(pass) == "conch-pw-2" {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("denied")
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if c.User() == "bothuser" && keyA[string(key.Marshal())] {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("denied")
		},
		ServerVersion: "SSH-2.0-conch-gossh_1.0",
	}
	cfg.AddHostKey(hostSigner())

	ln, err := net.Listen("tcp", "0.0.0.0:2223")
	if err != nil {
		panic(err)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(c, cfg)
	}
}

func handle(nConn net.Conn, cfg *ssh.ServerConfig) {
	conn, chans, reqs, err := ssh.NewServerConn(nConn, cfg)
	if err != nil {
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		switch nc.ChannelType() {
		case "session":
			go session(nc)
		case "direct-tcpip":
			go directTCPIP(nc)
		default:
			nc.Reject(ssh.UnknownChannelType, "unsupported")
		}
	}
}

type ptyReq struct {
	Term                   string
	Cols, Rows, Wpx, Hpx   uint32
	Modes                  string
}

func session(nc ssh.NewChannel) {
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	term := "vt100"
	for req := range reqs {
		switch req.Type {
		case "pty-req":
			var p ptyReq
			ssh.Unmarshal(req.Payload, &p)
			term = p.Term
			req.Reply(true, nil)
		case "shell":
			req.Reply(true, nil)
			// no real PTY device here: echo TERM so PTY tests can assert it,
			// then act as a trivial line echo until the channel closes.
			fmt.Fprintf(ch, "TERM=%s\r\n", term)
			go func() { io.Copy(ch, ch); ch.Close() }()
		case "exec":
			var e struct{ Cmd string }
			ssh.Unmarshal(req.Payload, &e)
			req.Reply(true, nil)
			runExec(ch, e.Cmd)
			return
		case "subsystem":
			var s struct{ Name string }
			ssh.Unmarshal(req.Payload, &s)
			if s.Name == "sftp" {
				req.Reply(true, nil)
				serveSFTP(ch)
				return
			}
			req.Reply(false, nil)
		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

func runExec(ch ssh.Channel, cmdline string) {
	cmd := exec.Command("/bin/sh", "-c", cmdline)
	cmd.Stdout = ch
	cmd.Stderr = ch.Stderr()
	status := 0
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			status = ee.ExitCode()
		} else {
			status = 127
		}
	}
	sendExit(ch, status)
	ch.Close()
}

func sendExit(ch ssh.Channel, code int) {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, uint32(code))
	ch.SendRequest("exit-status", false, payload)
}

func directTCPIP(nc ssh.NewChannel) {
	var m struct {
		Host       string
		Port       uint32
		OrigHost   string
		OrigPort   uint32
	}
	ssh.Unmarshal(nc.ExtraData(), &m)
	dst, err := net.Dial("tcp", fmt.Sprintf("%s:%d", m.Host, m.Port))
	if err != nil {
		nc.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		dst.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	go func() { io.Copy(ch, dst); ch.Close() }()
	go func() { io.Copy(dst, ch); dst.Close() }()
}

func serveSFTP(ch ssh.Channel) {
	srv, err := sftp.NewServer(ch)
	if err != nil {
		ch.Close()
		return
	}
	srv.Serve()
	srv.Close()
	sendExit(ch, 0)
	ch.Close()
}
