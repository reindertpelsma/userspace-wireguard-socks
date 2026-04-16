// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"unsafe"
)

func main() {
	if len(os.Args) < 5 {
		fmt.Fprintf(os.Stderr, "usage: %s <tcp|udp|stress> <ip> <port> <message> [workers loops]\n", os.Args[0])
		os.Exit(2)
	}
	mode := os.Args[1]
	ip := os.Args[2]
	port, err := strconv.Atoi(os.Args[3])
	if err != nil {
		panic(err)
	}
	message := os.Args[4]
	switch mode {
	case "tcp":
		os.Exit(runTCP(ip, port, message, true))
	case "udp":
		os.Exit(runUDP(ip, port, message))
	case "stress":
		workers := 6
		loops := 8
		if len(os.Args) >= 6 {
			if workers, err = strconv.Atoi(os.Args[5]); err != nil {
				panic(err)
			}
		}
		if len(os.Args) >= 7 {
			if loops, err = strconv.Atoi(os.Args[6]); err != nil {
				panic(err)
			}
		}
		os.Exit(runStress(ip, port, message, workers, loops))
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q\n", mode)
		os.Exit(2)
	}
}

func runTCP(ip string, port int, message string, print bool) int {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "socket:", err)
		return 1
	}
	defer syscall.Close(fd)
	addr := &syscall.SockaddrInet4{Port: port}
	copy(addr.Addr[:], net.ParseIP(ip).To4())
	if err := syscall.Connect(fd, addr); err != nil {
		fmt.Fprintln(os.Stderr, "connect:", err)
		return 1
	}
	if _, err := syscall.Write(fd, []byte(message)); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		return 1
	}
	buf := make([]byte, len(message))
	if _, err := syscall.Read(fd, buf); err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		return 1
	}
	if print {
		fmt.Printf("%s", string(buf))
	}
	if string(buf) != message {
		return 1
	}
	return 0
}

func runUDP(ip string, port int, message string) int {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "socket:", err)
		return 1
	}
	defer syscall.Close(fd)
	addr := &syscall.SockaddrInet4{Port: port}
	copy(addr.Addr[:], net.ParseIP(ip).To4())
	if err := syscall.Connect(fd, addr); err != nil {
		fmt.Fprintln(os.Stderr, "connect:", err)
		return 1
	}
	if _, err := syscall.Write(fd, []byte(message)); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		return 1
	}
	buf := make([]byte, len(message))
	n, _, errno := syscall.Syscall6(syscall.SYS_RECVFROM, uintptr(fd), uintptr(binaryData(buf)), uintptr(len(buf)), 0, 0, 0)
	if errno != 0 {
		fmt.Fprintln(os.Stderr, "recvfrom:", errno)
		return 1
	}
	got := string(buf[:n])
	fmt.Printf("%s", got)
	if got != message {
		return 1
	}
	return 0
}

func runStress(ip string, port int, message string, workers, loops int) int {
	var wg sync.WaitGroup
	errc := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < loops; i++ {
				tag := fmt.Sprintf("%s-%d-%d", message, worker, i)
				if runTCP(ip, port, tag, false) != 0 {
					errc <- fmt.Errorf("tcp loop %d/%d failed", worker, i)
					return
				}
			}
		}(worker)
	}
	wg.Wait()
	close(errc)
	if err := <-errc; err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Print("stress-ok")
	return 0
}

func binaryData(buf []byte) unsafe.Pointer {
	if len(buf) == 0 {
		return nil
	}
	return unsafe.Pointer(&buf[0])
}
