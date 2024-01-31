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
  "path/filepath"
)

var Version = "1.0.2"

const (
  bufSize = 65535
  udpIdleTimeout = time.Minute * 5
)

type Args struct {
  fwdrs []string
  logFile string
  logFileMutex sync.Mutex
}

type UDPConn struct {
  dst *net.UDPConn
  txRxBytes [2]float64
  lastActivity time.Time
}

func main() {
  fmt.Fprintf(os.Stdout, "PortFwd v%s - TCP/UDP Port Forwarder\n", Version)
  fmt.Fprintf(os.Stdout, "Copyright (c) 2024 Chris Mason <chris@netnix.org>\n\n")

  if args, err := parseArgs(); err == nil {
    if len(args.logFile) > 0 {
      if err := log(&args, "[%s] Starting PortFwd v%s...\n", time.Now().Format(time.StampMilli), Version); err == nil {
        fmt.Fprintf(os.Stdout, "Logging to %s...\n", args.logFile)

      } else {
        return
      }
    }

    var wgf sync.WaitGroup
    for _, fwdr := range args.fwdrs {
      switch efwdr := strings.Split(fwdr, ":"); efwdr[0] {
        case "tcp":
          wgf.Add(1)
          go tcpForwarder(efwdr[1:], &wgf, &args)

        case "udp":
          wgf.Add(1)
          go udpForwarder(efwdr[1:], &wgf, &args)
      }
    }
    wgf.Wait()

  } else {
    if len(err.Error()) > 0 {
      fmt.Fprintf(os.Stderr, "Error: %v\n", err)

    } else {
      fmt.Fprintf(os.Stderr, "Usage: portfwd -tcp [bind_host:]<listen_port>:<remote_host>:<remote_port>\n")
      fmt.Fprintf(os.Stderr, "               -udp [bind_host:]<listen_port>:<remote_host>:<remote_port>\n")
      fmt.Fprintf(os.Stderr, "               -logfile <portfwd.log>\n")
      fmt.Fprintf(os.Stderr, "               -config <portfwd.conf>\n")
    }
  }
}

func parseArgs() (Args, error) {
  var args Args

  rfwdr := regexp.MustCompile(`^(:?(?:[0-9]+\.){3}[0-9]+:)?[0-9]+:(?:[0-9]+\.){3}[0-9]+:[0-9]+$`)

  for i := 1; i < len(os.Args); i++ {
    if smatch(os.Args[i], "-tcp", 2) || smatch(os.Args[i], "-udp", 2) || smatch(os.Args[i], "-config", 2) || smatch(os.Args[i], "-logfile", 2) {
      if (len(os.Args) > (i + 1)) && !strings.HasPrefix(os.Args[i + 1], "-") {
        if smatch(os.Args[i], "-config", 2) {
          if file, err := os.Open(os.Args[i + 1]); err == nil {
            defer file.Close()

            s := bufio.NewScanner(file)

            for s.Scan() {
              t := strings.TrimSpace(s.Text())
              if strings.HasPrefix(t, "tcp") || strings.HasPrefix(t, "udp") {
                os.Args = append(os.Args, strings.Fields("-" + t)...)

              } else if (len(t) > 0) && !strings.HasPrefix(t, "#") {
                return args, fmt.Errorf("invalid configuration: %s", t)
              }
            }

            if err := s.Err(); err != nil {
              return args, err
            }
          } else {
            return args, err
          }
        } else if smatch(os.Args[i], "-logfile", 2) {
          if len(args.logFile) == 0 {
            var err error
            if args.logFile, err = filepath.Abs(os.Args[i + 1]); err != nil {
              return args, err
            }
          } else {
            return args, fmt.Errorf("")
          }
        } else {
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

func smatch(a string, b string, mlen int) bool {
  alen := len(a)
  if alen >= mlen {
    if len(b) < alen {
      alen = len(b)
    }
    return a == b[:alen]
  }
  return false
}

func formatBytes(b float64) string {
  var u string
  for _, u = range []string{"", "k", "M", "G", "T", "P", "E"} {
    if b >= 1000 {
      b /= 1000

    } else {
      break
    }
  }
  r := strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.2f", b), "0"), ".")
  return fmt.Sprintf("%s %sB", r, u)
}

func log(args *Args, f string, a ...interface{}) error {
  if len(args.logFile) > 0 {
    args.logFileMutex.Lock()
    defer args.logFileMutex.Unlock()

    if file, err := os.OpenFile(args.logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err == nil {
      defer file.Close()

      w := bufio.NewWriter(file)
      fmt.Fprintf(w, f, a...)
      w.Flush()

    } else {
      fmt.Fprintf(os.Stderr, "Error: %v\n", err)
      return err
    }
  } else {
    fmt.Fprintf(os.Stdout, f, a...)
  }
  return nil
}

func udpForwarder(fwdr []string, wgf *sync.WaitGroup, args *Args) {
  defer wgf.Done()

  var udpConnsMutex sync.RWMutex
  udpConns := make(map[string]*UDPConn)

  if udpAddr, err := net.ResolveUDPAddr("udp", fwdr[0] + ":" + fwdr[1]); err == nil {
    if s, err := net.ListenUDP("udp", udpAddr); err == nil {
      defer s.Close()

      if t, err := net.ResolveUDPAddr("udp", fwdr[2] + ":" + fwdr[3]); err == nil {
        buf := make([]byte, bufSize)

        log(args, "[%s] Creating UDP Forwarder: %s -> %s...\n", time.Now().Format(time.StampMilli), fwdr[0] + ":" + fwdr[1], fwdr[2] + ":" + fwdr[3])

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
              txRxBytes := udpConns[k].txRxBytes
              delete(udpConns, k)
              udpConnsMutex.Unlock()
              log(args, "- [%s] UDP: %s -> %s (Tx: %s, Rx: %s)\n", time.Now().Format(time.StampMilli), k, dst, formatBytes(txRxBytes[0]), formatBytes(txRxBytes[1]))
            }
          }
        }(udpConns, fwdr[2] + ":" + fwdr[3], &udpConnsMutex)

        for {
          if n, addr, err := s.ReadFrom(buf); err == nil {
            udpConnsMutex.RLock()
            u, ok := udpConns[addr.String()]
            udpConnsMutex.RUnlock()

            if !ok {
              log(args, "+ [%s] UDP: %s -> %s\n", time.Now().Format(time.StampMilli), addr, fwdr[2] + ":" + fwdr[3])

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
                      u.txRxBytes[1] += float64(n)
                      udpConnsMutex.Unlock()

                    } else {
                      break
                    }
                  }
                }(u, s, addr.(*net.UDPAddr))
                ok = true

              } else {
                log(args, "! [%s] Error: %v\n", time.Now().Format(time.StampMilli), err)
              }
            }

            if ok {
              u.dst.Write(buf[:n])
              udpConnsMutex.Lock()
              u.lastActivity = time.Now()
              u.txRxBytes[0] += float64(n)
              udpConnsMutex.Unlock()
            }
          } else {
            log(args, "! [%s] Error: %v\n", time.Now().Format(time.StampMilli), err)
          }
        }
      } else {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
      }
    } else {
      fmt.Fprintf(os.Stderr, "Error: %v\n", err)
    }
  } else {
    fmt.Fprintf(os.Stderr, "Error: %v\n", err)
  }
}

func tcpForwarder(fwdr []string, wgf *sync.WaitGroup, args *Args) {
  defer wgf.Done()

  if s, err := net.Listen("tcp", fwdr[0] + ":" + fwdr[1]); err == nil {
    var wgc sync.WaitGroup
    defer s.Close()

    log(args, "[%s] Creating TCP Forwarder: %s -> %s...\n", time.Now().Format(time.StampMilli), fwdr[0] + ":" + fwdr[1], fwdr[2] + ":" + fwdr[3])

    for {
      if c, err := s.Accept(); err == nil {
        wgc.Add(1)

        log(args, "+ [%s] TCP: %s -> %s\n", time.Now().Format(time.StampMilli), c.RemoteAddr(), fwdr[2] + ":" + fwdr[3])

        go func(nc net.Conn, dst string) {
          defer wgc.Done()
          defer nc.Close()

          if t, err := net.Dial("tcp", fwdr[2] + ":" + fwdr[3]); err == nil {
            defer t.Close()

            var txRxBytes [2]float64
            go forwardTcp(nc, t, &txRxBytes[0])
            forwardTcp(t, nc, &txRxBytes[1])

            log(args, "- [%s] TCP: %s -> %s (Tx: %s, Rx: %s)\n", time.Now().Format(time.StampMilli), nc.RemoteAddr(), dst, formatBytes(txRxBytes[0]), formatBytes(txRxBytes[1]))

          } else {
            log(args, "! [%s] Error: %v\n", time.Now().Format(time.StampMilli), err)
          }
        }(c, fwdr[2] + ":" + fwdr[3])

      } else {
        log(args, "! [%s] Error: %v\n", time.Now().Format(time.StampMilli), err)
      }
    }
    wgc.Wait()

  } else {
    fmt.Fprintf(os.Stderr, "Error: %v\n", err)
  }
}

func forwardTcp(src net.Conn, dst net.Conn, txRxBytes *float64) {
  r := bufio.NewReader(src)
  w := bufio.NewWriter(dst)

  buf := make([]byte, bufSize)

  for {
    if n, err := r.Read(buf); err == nil {
      w.Write(buf[:n])
      w.Flush()
      *txRxBytes += float64(n)

    } else {
      dst.Close()
      break
    }
  }
}
