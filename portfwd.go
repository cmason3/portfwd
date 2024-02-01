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
  "syscall"
  "os/signal"
  "path/filepath"
)

var Version = "1.0.4-dev"

const (
  bufSize = 65535
  udpIdleTimeout = time.Minute * 5
)

type Args struct {
  fwdrs map[string][]string
  logFile string
  logFileMutex sync.Mutex
  shutdown chan struct{}
}

type UDPConn struct {
  target string
  dst *net.UDPConn
  txRxBytes [2]float64
  lastActivity time.Time
}

func main() {
  fmt.Fprintf(os.Stdout, "PortFwd v%s - TCP/UDP Port Forwarder\n", Version)
  fmt.Fprintf(os.Stdout, "Copyright (c) 2024 Chris Mason <chris@netnix.org>\n\n")

  if args, err := parseArgs(); err == nil {
    if len(args.logFile) > 0 {
      if err := log(&args, "[%s] Starting PortFwd v%s...\n", time.Now().Format(time.StampMilli), Version); err != nil {
        os.Exit(1)
      }
    }

    signals := make(chan os.Signal, 1)
    signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
    args.shutdown = make(chan struct{})

    go func(args *Args) {
      log(args, "[%s] Caught '%s' Signal... Terminating...\n", time.Now().Format(time.StampMilli), <-signals)
      close(args.shutdown)
    }(&args)

    var wgf sync.WaitGroup
    for fwdr, targets := range args.fwdrs {
      switch efwdr := strings.Split(fwdr, ":"); efwdr[0] {
        case "t":
          wgf.Add(1)
          go tcpForwarder(efwdr[1:], targets, &wgf, &args)

        case "u":
          wgf.Add(1)
          go udpForwarder(efwdr[1:], targets, &wgf, &args)
      }
    }
    wgf.Wait()

    if len(args.logFile) > 0 {
      log(&args, "[%s] PortFwd Terminated\n", time.Now().Format(time.StampMilli))
    }
  } else {
    if len(err.Error()) > 0 {
      fmt.Fprintf(os.Stderr, "Error: %v\n", err)

    } else {
      fmt.Fprintf(os.Stderr, "Usage: portfwd -tcp [bind_host:]<listen_port>:<remote_host>:<remote_port>\n")
      fmt.Fprintf(os.Stderr, "               -udp [bind_host:]<listen_port>:<remote_host>:<remote_port>\n")
      fmt.Fprintf(os.Stderr, "               -logfile <portfwd.log>\n")
      fmt.Fprintf(os.Stderr, "               -config <portfwd.conf>\n")
    }
    os.Exit(1)
  }
}

func parseArgs() (Args, error) {
  var args Args
  args.fwdrs = make(map[string][]string)

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

              efwdr := strings.Split(fwdr, ":")
              mkey := os.Args[i][1:2] + ":" + strings.Join(efwdr[:2], ":")
              args.fwdrs[mkey] = append(args.fwdrs[mkey], strings.Join(efwdr[2:], ":"))

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

func udpForwarder(fwdr []string, targets []string, wgf *sync.WaitGroup, args *Args) {
  defer wgf.Done()

  var udpConnsMutex sync.RWMutex
  udpConns := make(map[string]*UDPConn)

  if udpAddr, err := net.ResolveUDPAddr("udp", fwdr[0] + ":" + fwdr[1]); err == nil {
    if s, err := net.ListenUDP("udp", udpAddr); err == nil {
      defer s.Close()

      var wgc sync.WaitGroup
      buf := make([]byte, bufSize)

      log(args, "[%s] Creating UDP Forwarder: %s -> %s...\n", time.Now().Format(time.StampMilli), fwdr[0] + ":" + fwdr[1], strings.Join(targets[:1], ","))

      wgc.Add(1)

      go func(udpConns map[string]*UDPConn, udpConnsMutex *sync.RWMutex, shutdown chan struct{}) {
        defer wgc.Done()
        var stop bool

        for {
          select {
            case <-shutdown:
              stop = true

            default:
          }

          var staleConns []string

          udpConnsMutex.RLock()
          if (len(udpConns) == 0) && stop {
            udpConnsMutex.RUnlock()
            break
          }
          for k, v := range udpConns {
            if v.lastActivity.Before(time.Now().Add(-udpIdleTimeout)) {
              v.dst.Close()
              staleConns = append(staleConns, k)
            }
          }
          udpConnsMutex.RUnlock()

          time.Sleep(time.Second * 5)

          for _, k := range staleConns {
            udpConnsMutex.Lock()
            txRxBytes := udpConns[k].txRxBytes
            target := udpConns[k].target
            delete(udpConns, k)
            udpConnsMutex.Unlock()
            log(args, "- [%s] UDP: %s -> %s (Tx: %s, Rx: %s)\n", time.Now().Format(time.StampMilli), k, target, formatBytes(txRxBytes[0]), formatBytes(txRxBytes[1]))
          }
        }
      }(udpConns, &udpConnsMutex, args.shutdown)

      go func(shutdown chan struct{}, udpConns map[string]*UDPConn, udpConnsMutex *sync.RWMutex) {
        <-shutdown
        s.Close()

        udpConnsMutex.Lock()
        for _, v := range udpConns {
          v.dst.Close()
          v.lastActivity = time.Time{}
        }
        udpConnsMutex.Unlock()
      }(args.shutdown, udpConns, &udpConnsMutex)

      for {
        if n, addr, err := s.ReadFrom(buf); err == nil {
          udpConnsMutex.RLock()
          u, ok := udpConns[addr.String()]
          udpConnsMutex.RUnlock()

          if !ok {
            target := strings.Split(targets[0], ":") // ALWAYS USE FIRST TARGET AT THE MOMENT
            log(args, "+ [%s] UDP: %s -> %s\n", time.Now().Format(time.StampMilli), addr, target[0] + ":" + target[1])

            if t, err := net.ResolveUDPAddr("udp", target[0] + ":" + target[1]); err == nil {
              if c, err := net.DialUDP("udp", nil, t); err == nil {
                u = &UDPConn {
                  dst: c,
                  target: target[0] + ":" + target[1],
                  lastActivity: time.Now(),
                }
  
                udpConnsMutex.Lock()
                udpConns[addr.String()] = u
                udpConnsMutex.Unlock()
  
                wgc.Add(1)
  
                go func(u *UDPConn, s *net.UDPConn, addr *net.UDPAddr) {
                  defer wgc.Done()
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
          break
        }
      }
      wgc.Wait()

      log(args, "[%s] Stopping UDP Forwarder: %s -> %s...\n", time.Now().Format(time.StampMilli), fwdr[0] + ":" + fwdr[1], strings.Join(targets[:1], ","))

    } else {
      fmt.Fprintf(os.Stderr, "Error: %v\n", err)
    }
  } else {
    fmt.Fprintf(os.Stderr, "Error: %v\n", err)
  }
}

func tcpForwarder(fwdr []string, targets []string, wgf *sync.WaitGroup, args *Args) {
  defer wgf.Done()

  if s, err := net.Listen("tcp", fwdr[0] + ":" + fwdr[1]); err == nil {
    var wgc sync.WaitGroup
    defer s.Close()

    log(args, "[%s] Creating TCP Forwarder: %s -> %s...\n", time.Now().Format(time.StampMilli), fwdr[0] + ":" + fwdr[1], strings.Join(targets[:1], ","))

    go func(shutdown chan struct{}) {
      <-shutdown
      s.Close()
    }(args.shutdown)

    for {
      if c, err := s.Accept(); err == nil {
        wgc.Add(1)

        target := strings.Split(targets[0], ":") // ALWAYS USE FIRST TARGET AT THE MOMENT
        log(args, "+ [%s] TCP: %s -> %s\n", time.Now().Format(time.StampMilli), c.RemoteAddr(), target[0] + ":" + target[1])

        go func(nc net.Conn, target string) {
          defer wgc.Done()
          defer nc.Close()

          if t, err := net.Dial("tcp", target); err == nil {
            defer t.Close()

            var txRxBytes [2]float64
            go forwardTcp(nc, t, &txRxBytes[0])
            forwardTcp(t, nc, &txRxBytes[1])

            log(args, "- [%s] TCP: %s -> %s (Tx: %s, Rx: %s)\n", time.Now().Format(time.StampMilli), nc.RemoteAddr(), target, formatBytes(txRxBytes[0]), formatBytes(txRxBytes[1]))

          } else {
            log(args, "! [%s] Error: %v\n", time.Now().Format(time.StampMilli), err)
          }
        }(c, target[0] + ":" + target[1])

      } else {
        break
      }
    }
    wgc.Wait()

    log(args, "[%s] Stopping TCP Forwarder: %s -> %s...\n", time.Now().Format(time.StampMilli), fwdr[0] + ":" + fwdr[1], strings.Join(targets[:1], ","))

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
