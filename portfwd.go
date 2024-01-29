/*
 * PortFwd - TCP/UDP Port Forwarder
 * Copyright (c) 2024 Chris Mason <chris@netnix.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package main

import (
  "os"
  "fmt"
  "net"
  "sync"
  "time"
  "bufio"
  "regexp"
  "strings"
)

var Version = "1.0.0"

const (
  bufSize = 65535
  udpIdleTimeout = time.Minute * 5
)

type Args struct {
  fwdrs []string
}

type UDPConn struct {
  dst *net.UDPConn
  lastActivity time.Time
}

func main() {
  fmt.Fprintf(os.Stderr, "PortFwd %s - TCP/UDP Port Forwarder\n", Version)
  fmt.Fprintf(os.Stderr, "Copyright (c) 2024 Chris Mason <chris@netnix.org>\n\n")

  if args, err := parseArgs(); err == nil {
    var wgf sync.WaitGroup
    for _, fwdr := range args.fwdrs {
      switch efwdr := strings.Split(fwdr, ":"); efwdr[0] {
        case "tcp":
          wgf.Add(1)
          go tcpForwarder(efwdr[1:], &wgf)
        case "udp":
          wgf.Add(1)
          go udpForwarder(efwdr[1:], &wgf)
      }
    }
    wgf.Wait()

  } else {
    if len(err.Error()) > 0 {
      fmt.Fprintf(os.Stderr, "error: %v\n", err)

    } else {
      fmt.Fprintf(os.Stderr, "Usage: portfwd -tcp [bind_host:]<listen_port>:<remote_host>:<remote_port>\n")
      fmt.Fprintf(os.Stderr, "               -udp [bind_host:]<listen_port>:<remote_host>:<remote_port>\n")
    }
  }
}

func parseArgs() (Args, error) {
  var args Args

  rfwdr := regexp.MustCompile(`^(:?(?:[0-9]+\.){3}[0-9]+:)?[0-9]+:(?:[0-9]+\.){3}[0-9]+:[0-9]+$`)

  for i := 1; i < len(os.Args); i++ {
    if (os.Args[i] == "-tcp") || (os.Args[i] == "-udp") {
      if (len(os.Args) > (i + 1)) && !strings.HasPrefix(os.Args[i + 1], "-") {
        for _, fwdr := range strings.Split(os.Args[i + 1], ",") {
          if rfwdr.MatchString(fwdr) {
            if strings.Count(fwdr, ":") == 2 {
              fwdr = "127.0.0.1:" + fwdr
            }
            args.fwdrs = append(args.fwdrs, os.Args[i][1:] + ":" + fwdr)

          } else {
            return args, fmt.Errorf("invalid forwarder: %s", fwdr)
          }
        }
        i += 1

      } else {
        return args, fmt.Errorf("invalid argument: %s", os.Args[i])
      }
    } else {
      return args, fmt.Errorf("unknown argument: %s", os.Args[i])
    }
  }
  if len(args.fwdrs) == 0 {
    return args, fmt.Errorf("")
  }
  return args, nil
}

func udpForwarder(fwdr []string, wgf *sync.WaitGroup) {
  defer wgf.Done()

  var udpConnsMutex sync.RWMutex
  udpConns := make(map[string]*UDPConn)

  if udpAddr, err := net.ResolveUDPAddr("udp", fwdr[0] + ":" + fwdr[1]); err == nil {
    if s, err := net.ListenUDP("udp", udpAddr); err == nil {
      defer s.Close()

      if t, err := net.ResolveUDPAddr("udp", fwdr[2] + ":" + fwdr[3]); err == nil {
        buf := make([]byte, bufSize)

        fmt.Printf("UDP Forwarder - %s -> %s...\n", fwdr[0] + ":" + fwdr[1], fwdr[2] + ":" + fwdr[3])

        go func(udpConns map[string]*UDPConn, dst string, udpConnsMutex *sync.RWMutex) {
          for {
            var staleConns []string

            udpConnsMutex.RLock()
            for k, v := range udpConns {
              if v.lastActivity.Before(time.Now().Add(-udpIdleTimeout)) {
                v.dst.Close()
                staleConns = append(staleConns, k)
              }
            }
            udpConnsMutex.RUnlock()

            time.Sleep(time.Second * 15)

            for _, k := range staleConns {
              udpConnsMutex.Lock()
              delete(udpConns, k)
              udpConnsMutex.Unlock()
              fmt.Printf("- [%s] UDP: %s -> %s\n", time.Now().Format(time.StampMilli), k, dst)
            }
          }
        }(udpConns, fwdr[2] + ":" + fwdr[3], &udpConnsMutex)

        for {
          if n, addr, err := s.ReadFrom(buf); err == nil {
            udpConnsMutex.RLock()
            u, ok := udpConns[addr.String()]
            udpConnsMutex.RUnlock()

            if !ok {
              fmt.Printf("+ [%s] UDP: %s -> %s\n", time.Now().Format(time.StampMilli), addr, fwdr[2] + ":" + fwdr[3])

              if c, err := net.DialUDP("udp", nil, t); err == nil {
                u = &UDPConn {
                  dst: c,
                  lastActivity: time.Now(),
                }

                udpConnsMutex.Lock()
                udpConns[addr.String()] = u
                udpConnsMutex.Unlock()

                go func(u *UDPConn, s *net.UDPConn, addr *net.UDPAddr) {
                  buf := make([]byte, bufSize)
                  
                  for { 
                    if n, _, err := u.dst.ReadFrom(buf); err == nil {
                      s.WriteToUDP(buf[:n], addr)
                      udpConnsMutex.Lock()
                      u.lastActivity = time.Now()
                      udpConnsMutex.Unlock()

                    } else {
                      break
                    }
                  }
                }(u, s, addr.(*net.UDPAddr))
                ok = true

              } else {
                fmt.Fprintf(os.Stderr, "error: %v\n", err)
              }
            }

            if ok {
              u.dst.Write(buf[:n])
              udpConnsMutex.Lock()
              u.lastActivity = time.Now()
              udpConnsMutex.Unlock()
            }
          } else {
            fmt.Fprintf(os.Stderr, "error: %v\n", err)
          }
        }
      } else {
        fmt.Fprintf(os.Stderr, "error: %v\n", err)
      }
    } else {
      fmt.Fprintf(os.Stderr, "error: %v\n", err)
    }
  } else {
    fmt.Fprintf(os.Stderr, "error: %v\n", err)
  }
}

func tcpForwarder(fwdr []string, wgf *sync.WaitGroup) {
  defer wgf.Done()

  if s, err := net.Listen("tcp", fwdr[0] + ":" + fwdr[1]); err == nil {
    var wgc sync.WaitGroup
    defer s.Close()

    fmt.Printf("TCP Forwarder - %s -> %s...\n", fwdr[0] + ":" + fwdr[1], fwdr[2] + ":" + fwdr[3])

    for {
      if c, err := s.Accept(); err == nil {
        wgc.Add(1)

        fmt.Printf("+ [%s] TCP: %s -> %s\n", time.Now().Format(time.StampMilli), c.RemoteAddr(), fwdr[2] + ":" + fwdr[3])

        go func(nc net.Conn, dst string) {
          defer wgc.Done()
          defer nc.Close()

          if t, err := net.Dial("tcp", fwdr[2] + ":" + fwdr[3]); err == nil {
            defer t.Close()
          
            go forwardTcp(nc, t)
            forwardTcp(t, nc)

            fmt.Printf("- [%s] TCP: %s -> %s\n", time.Now().Format(time.StampMilli), nc.RemoteAddr(), dst)

          } else {
            fmt.Fprintf(os.Stderr, "error: %v\n", err)
          }
        }(c, fwdr[2] + ":" + fwdr[3])

      } else {
        fmt.Fprintf(os.Stderr, "error: %v\n", err)
      }
    }
    wgc.Wait()

  } else {
    fmt.Fprintf(os.Stderr, "error: %v\n", err)
  }
}

func forwardTcp(src net.Conn, dst net.Conn) {
  r := bufio.NewReader(src)
  w := bufio.NewWriter(dst)

  buf := make([]byte, bufSize)

  for {
    if n, err := r.Read(buf); err == nil {
      w.Write(buf[:n])
      w.Flush()

    } else {
      dst.Close()
      break
    }
  }
}
