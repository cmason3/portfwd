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
  "math"
  "bufio"
  "regexp"
  "strings"
  "syscall"
  "os/signal"
  "path/filepath"
  "crypto/cipher"
  "encoding/binary"
  "filippo.io/mlkem768/xwing"
  "golang.org/x/crypto/chacha20poly1305"
)

var Version = "1.1.0"

const (
  bufSize = 65535
  udpIdleTimeout = time.Minute * 5
)

type Args struct {
  fwdrs map[string][]string
  shutdown chan struct{}
  logFileMutex sync.Mutex
  logFile string
  mode string
}

type UDPConn struct {
  target string
  dst *net.UDPConn
  txRxBytes [2]float64
  lastActivity time.Time
}

type CryptoKeys struct {
  public []byte
  private []byte
  encrypt [2]cipher.AEAD
  decrypt [2]cipher.AEAD
}

func main() {
  if args, err := parseArgs(); err == nil {
    if len(args.logFile) > 0 {
      if err := log(&args, "Starting PortFwd v%s...\n", Version); err != nil {
        os.Exit(1)
      }
    }

    signals := make(chan os.Signal, 1)
    signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
    args.shutdown = make(chan struct{})

    go func(args *Args) {
      log(args, "Caught '%s' Signal... Terminating...\n", <-signals)
      close(args.shutdown)
    }(&args)

    var wgf sync.WaitGroup
    for fwdr, targets := range args.fwdrs {
      if strings.HasPrefix(fwdr, "t:") {
        wgf.Add(1)
        go tcpForwarder(fwdr[2:], targets, &wgf, &args)

      } else if strings.HasPrefix(fwdr, "u:") {
        wgf.Add(1)
        go udpForwarder(fwdr[2:], targets, &wgf, &args)
      }
    }
    wgf.Wait()

    if len(args.logFile) > 0 {
      log(&args, "PortFwd Terminated\n")
    }
  } else {
    fmt.Fprintf(os.Stderr, "PortFwd v%s - TCP/UDP Port Forwarder\n", Version)
    fmt.Fprintf(os.Stderr, "Copyright (c) 2024 Chris Mason <chris@netnix.org>\n\n")

    if len(err.Error()) > 0 {
      fmt.Fprintf(os.Stderr, "Error: %v\n", err)

    } else {
      fmt.Fprintf(os.Stderr, "Usage: portfwd -tcp [<bind_host>:]<listen_port>[s]:<remote_host>:<remote_port>[s]\n")
      fmt.Fprintf(os.Stderr, "               -udp [<bind_host>:]<listen_port>:<remote_host>:<remote_port>\n")
      fmt.Fprintf(os.Stderr, "               -logfile <portfwd.log>\n")
      fmt.Fprintf(os.Stderr, "               -config <portfwd.conf>\n")
      fmt.Fprintf(os.Stderr, "               -ft-tcp\n")
    }
    os.Exit(1)
  }
}

func parseArgs() (Args, error) {
  var args Args
  args.fwdrs = make(map[string][]string)
  args.mode = "RR"

  rfwdr := regexp.MustCompile(`(?i)^(?:(\[[0-9A-F:.]+\]|[^\s:]+):)?([0-9]+s?):(\[[0-9A-F:.]+\]|[^\s:]+):([0-9]+s?)$`)

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
            if m := rfwdr.FindStringSubmatch(fwdr); len(m) == 5 {
              if len(m[1]) == 0 {
                m[1] = "localhost"
              }

              rst := regexp.MustCompile(`(?i)s$`)
              m[2] = rst.ReplaceAllString(m[2], "|ST")
              m[4] = rst.ReplaceAllString(m[4], "|ST")
              mkey := os.Args[i][1:2] + ":" + strings.Join(m[1:3], ":")
              args.fwdrs[mkey] = append(args.fwdrs[mkey], strings.Join(m[3:], ":"))

            } else {
              return args, fmt.Errorf("invalid forwarder: %s", fwdr)
            }
          }
        }
        i += 1

      } else {
        return args, fmt.Errorf("invalid argument: %s", os.Args[i])
      }
    } else if smatch(os.Args[i], "-ft-tcp", 2) {
      args.mode = "FT"

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

func ternary(b bool, t string, f string) string {
  if b {
    return t

  } else {
    return f
  }
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

func log(args *Args, f string, a ...any) error {
  ts := fmt.Sprintf("[%s] ", time.Now().Format(time.StampMilli))

  if len(args.logFile) > 0 {
    args.logFileMutex.Lock()
    defer args.logFileMutex.Unlock()

    if file, err := os.OpenFile(args.logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err == nil {
      defer file.Close()

      w := bufio.NewWriter(file)
      fmt.Fprintf(w, ts + f, a...)
      w.Flush()

    } else {
      fmt.Fprintf(os.Stderr, "Error: %v\n", err)
      return err
    }
  } else {
    if _, defined := os.LookupEnv("JOURNAL_STREAM"); defined {
      fmt.Fprintf(os.Stdout, f, a...)

    } else {
      fmt.Fprintf(os.Stdout, ts + f, a...)
    }
  }
  return nil
}

func udpFlowId(src string, s *net.UDPConn, dst string) string {
  return fmt.Sprintf("%s[%s] -> %s", src, strings.Split(s.LocalAddr().String(), ":")[1], dst)
}

func udpForwarder(fwdr string, targets []string, wgf *sync.WaitGroup, args *Args) {
  defer wgf.Done()

  var udpConnsMutex sync.RWMutex
  udpConns := make(map[string]*UDPConn)

  if udpAddr, err := net.ResolveUDPAddr("udp", fwdr); err == nil {
    if s, err := net.ListenUDP("udp", udpAddr); err == nil {
      defer s.Close()

      var connCount int
      var wgc sync.WaitGroup
      buf := make([]byte, bufSize)

      stargets := fmt.Sprintf("[%s]", strings.Join(targets, ", "))
      log(args, "Creating UDP Forwarder: %s -> RR:%s...\n", fwdr, stargets)

      wgc.Add(1)

      go func(s *net.UDPConn, udpConns map[string]*UDPConn, udpConnsMutex *sync.RWMutex, shutdown chan struct{}, args *Args) {
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
            target := udpConns[k].target
            txRxBytes := udpConns[k].txRxBytes
            delete(udpConns, k)
            udpConnsMutex.Unlock()

            log(args, "- UDP: %s (Tx: %s, Rx: %s)\n", udpFlowId(k, s, target), formatBytes(txRxBytes[0]), formatBytes(txRxBytes[1]))
          }
        }
      }(s, udpConns, &udpConnsMutex, args.shutdown, args)

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
            target := targets[connCount % len(targets)]

            if t, err := net.ResolveUDPAddr("udp", target); err == nil {
              log(args, "+ UDP: %s\n", udpFlowId(addr.String(), s, t.String()))

              if c, err := net.DialUDP("udp", nil, t); err == nil {
                u = &UDPConn {
                  dst: c,
                  target: target,
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
                log(args, "- UDP: %s (Error: %v)\n", udpFlowId(addr.String(), s, t.String()), err)
              }
            } else {
              log(args, "+ UDP: %s\n", udpFlowId(addr.String(), s, target))
              log(args, "- UDP: %s (Error: %v)\n", udpFlowId(addr.String(), s, target), err)
            }
          }

          if ok {
            u.dst.Write(buf[:n])
            udpConnsMutex.Lock()
            u.lastActivity = time.Now()
            u.txRxBytes[0] += float64(n)
            udpConnsMutex.Unlock()
          }
          connCount += 1

        } else {
          break
        }
      }
      wgc.Wait()

      log(args, "Stopping UDP Forwarder: %s -> RR:%s...\n", fwdr, stargets)

    } else {
      fmt.Fprintf(os.Stderr, "Error: %v\n", err)
    }
  } else {
    fmt.Fprintf(os.Stderr, "Error: %v\n", err)
  }
}

func tcpFlowId(src net.Conn, dst string, srcStun bool, dstStun bool) string {
  return fmt.Sprintf("%s[%s%s] -> %s%s", src.RemoteAddr(), strings.Split(src.LocalAddr().String(), ":")[1], ternary(srcStun, "|ST", ""), dst, ternary(dstStun, "|ST", ""))
}

func tcpForwarder(fwdr string, targets []string, wgf *sync.WaitGroup, args *Args) {
  defer wgf.Done()

  srcStun := strings.HasSuffix(fwdr, "|ST")

  if tcpAddr, err := net.ResolveTCPAddr("tcp", strings.TrimSuffix(fwdr, "|ST")); err == nil {
    if s, err := net.ListenTCP("tcp", tcpAddr); err == nil {
      var wgc sync.WaitGroup
      var targetMutex sync.Mutex
      var connCount int
      defer s.Close()

      stargets := fmt.Sprintf("[%s]", strings.Join(targets, ", "))
      log(args, "Creating TCP Forwarder: %s -> %s:%s...\n", fwdr, args.mode, stargets)

      go func(shutdown chan struct{}) {
        <-shutdown
        s.Close()
      }(args.shutdown)

      for {
        if c, err := s.Accept(); err == nil {
          var target string

          if args.mode == "RR" {
            target = targets[connCount % len(targets)]

          } else if args.mode == "FT" {
            targetMutex.Lock()
            target = targets[0]
            targetMutex.Unlock()
          }

          wgc.Add(1)

          go func(c net.Conn, target string, args *Args, targetMutex *sync.Mutex, srcStun bool) {
            defer wgc.Done()
            defer c.Close()

            dstStun := strings.HasSuffix(target, "|ST")
            target = strings.TrimSuffix(target, "|ST")

            if tcpAddr, err := net.ResolveTCPAddr("tcp", target); err == nil {
              log(args, "+ TCP: %s\n", tcpFlowId(c, tcpAddr.String(), srcStun, dstStun))

              if t, err := net.DialTimeout(tcpAddr.Network(), tcpAddr.String(), time.Second * 5); err == nil {
                var cryptoKeys CryptoKeys
                var todo sync.WaitGroup

                defer t.Close()

                if srcStun || dstStun {
                  var err error
                  if cryptoKeys.public, cryptoKeys.private, err = xwing.GenerateKey(); err == nil {
                    hdr := []byte{0x01, 0x00, 0x00}
                    binary.BigEndian.PutUint16(hdr[1:], uint16(len(cryptoKeys.public)))

                    if srcStun {
                      sw := bufio.NewWriter(c)
                      sw.Write(append(hdr, cryptoKeys.public...))
                      sw.Flush()
                      todo.Add(1)
                    }
                    if dstStun {
                      dw := bufio.NewWriter(t)
                      dw.Write(append(hdr, cryptoKeys.public...))
                      dw.Flush()
                      todo.Add(1)
                    }
                  } else {
                    log(args, "- TCP: %s (Error: %v)\n", tcpFlowId(c, tcpAddr.String(), srcStun, dstStun), err)
                    return
                  }
                }

                var txRxBytes [2]float64
                var wgs sync.WaitGroup
                wgs.Add(2)

                go forwardTcp(c, t, srcStun, dstStun, &cryptoKeys, 0, &todo, &txRxBytes[0], args, &wgs)
                forwardTcp(t, c, dstStun, srcStun, &cryptoKeys, 1, &todo, &txRxBytes[1], args, &wgs)
                wgs.Wait()

                log(args, "- TCP: %s (Tx: %s, Rx: %s)\n", tcpFlowId(c, tcpAddr.String(), srcStun, dstStun), formatBytes(txRxBytes[0]), formatBytes(txRxBytes[1]))
                return

              } else {
                log(args, "- TCP: %s (Error: %v)\n", tcpFlowId(c, tcpAddr.String(), srcStun, dstStun), err)
              }
            } else {
              log(args, "+ TCP: %s\n", tcpFlowId(c, target, srcStun, dstStun), err)
              log(args, "- TCP: %s (Error: %v)\n", tcpFlowId(c, target, srcStun, dstStun), err)
            }

            if args.mode == "FT" {
              targetMutex.Lock()
              for i, t := range targets {
                if (t == target) && (i != (len(targets) - 1)) {
                  copy(targets[i:], targets[i + 1:])
                  targets[len(targets) - 1] = t
                  break
                }
              }
              targetMutex.Unlock()
            }
          }(c, target, args, &targetMutex, srcStun)
          connCount += 1

        } else {
          break
        }
      }
      wgc.Wait()

      log(args, "Stopping TCP Forwarder: %s -> %s:%s...\n", fwdr, args.mode, stargets)

    } else {
      fmt.Fprintf(os.Stderr, "Error: %v\n", err)
    }
  } else {
    fmt.Fprintf(os.Stderr, "Error: %v\n", err)
  }
}

func forwardTcp(src net.Conn, dst net.Conn, srcStun bool, dstStun bool, cryptoKeys *CryptoKeys, keyId int, todo *sync.WaitGroup, txRxBytes *float64, args *Args, wgs *sync.WaitGroup) {
  var pktSeqNum uint64
  var rbuf []byte
  var oH int

  defer wgs.Done()

  sr := bufio.NewReader(src)
  dw := bufio.NewWriter(dst)
  kemRequired := srcStun

  if !srcStun && dstStun {
    oH = 3 + chacha20poly1305.Overhead
  }

  buf := make([]byte, bufSize - oH)
  nonce := make([]byte, chacha20poly1305.NonceSize)

  o: for {
    if n, err := sr.Read(buf); err == nil {
      if srcStun {
        rbuf = append(rbuf, buf[:n]...)
      }
      for {
        if srcStun {
          if len(rbuf) > 0 {
            if rbuf[0] == 0x01 {
              if len(rbuf) > 3 {
                n = int(binary.BigEndian.Uint16(rbuf[1:3]))

                if len(rbuf) >= (n + 3) {
                  copy(buf, rbuf[3:n + 3])
                  rbuf = rbuf[n + 3:]

                } else {
                  continue o
                }
              } else {
                continue o
              }
            } else {
              if kemRequired {
                todo.Done()
              }
              log(args, "! TCP: %s (Error: portfwd: protocol version mismatch)\n", tcpFlowId(src, dst.RemoteAddr().String(), srcStun, dstStun))
              src.Close()
              break o
            }
          } else {
            continue o
          }
        }
        if kemRequired {
          if pktSeqNum == 0 {
            if ciphertext, skey, err := xwing.Encapsulate(buf[:n]); err == nil {
              var err error
              if cryptoKeys.encrypt[keyId], err = chacha20poly1305.New(skey); err == nil {
                sw := bufio.NewWriter(src)
                hdr := []byte{0x01, 0x00, 0x00}
                binary.BigEndian.PutUint16(hdr[1:], uint16(len(ciphertext)))
                sw.Write(append(hdr, ciphertext...))
                sw.Flush()

              } else {
                log(args, "! TCP: %s (Error: %v)\n", tcpFlowId(src, dst.RemoteAddr().String(), srcStun, dstStun), err)
                src.Close()
                todo.Done()
                break o
              }
            } else {
              log(args, "! TCP: %s (Error: %v)\n", tcpFlowId(src, dst.RemoteAddr().String(), srcStun, dstStun), err)
              src.Close()
              todo.Done()
              break o
            }
          } else if pktSeqNum == 1 {
            todo.Done()

            if skey, err := xwing.Decapsulate(cryptoKeys.private, buf[:n]); err == nil {
              var err error
              if cryptoKeys.decrypt[keyId], err = chacha20poly1305.New(skey); err == nil {
                kemRequired = false
                pktSeqNum = 0
                continue

              } else {
                log(args, "! TCP: %s (Error: %v)\n", tcpFlowId(src, dst.RemoteAddr().String(), srcStun, dstStun), err)
                src.Close()
                break o
              }
            } else {
              log(args, "! TCP: %s (Error: %v)\n", tcpFlowId(src, dst.RemoteAddr().String(), srcStun, dstStun), err)
              src.Close()
              break o
            }
          }
        } else {
          todo.Wait()

          if srcStun {
            binary.BigEndian.PutUint64(nonce, pktSeqNum)
            if _, err := cryptoKeys.decrypt[keyId].Open(buf[:0], nonce, buf[:n], nil); err == nil {
              n -= chacha20poly1305.Overhead

            } else {
              log(args, "! TCP: %s (Error: %v)\n", tcpFlowId(src, dst.RemoteAddr().String(), srcStun, dstStun), err)
              src.Close()
              break o
            }
          }

          if dstStun {
            if cryptoKeys.encrypt[keyId ^ 1] != nil {
              hdr := []byte{0x01, 0x00, 0x00}
              binary.BigEndian.PutUint16(hdr[1:], uint16(n + chacha20poly1305.Overhead))
              binary.BigEndian.PutUint64(nonce, pktSeqNum)
              ciphertext := cryptoKeys.encrypt[keyId ^ 1].Seal(nil, nonce, buf[:n], nil)
              dw.Write(append(hdr, ciphertext...))

            } else {
              break o
            }
          } else {
            dw.Write(buf[:n])
          }
          dw.Flush()

          *txRxBytes += float64(n)
        }

        if srcStun || dstStun {
          if math.MaxUint64 > pktSeqNum {
            pktSeqNum++

          } else {
            log(args, "! TCP: %s (Error: portfwd: nonce re-use prohibited)\n", tcpFlowId(src, dst.RemoteAddr().String(), srcStun, dstStun))
            src.Close()
            break o
          }
        }
        if !srcStun {
          continue o
        }
      }
    } else {
      break
    }
  }
  dst.Close()
}
