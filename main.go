package main

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

func client(sAddr *net.UDPAddr, wg *sync.WaitGroup) {
	cAddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		log.Fatalln(err)
	}

	cConn, err := net.DialUDP("udp", cAddr, sAddr)
	if err != nil {
		log.Fatalln(err)
	}

	buf := []byte("hello")
	echo := make([]byte, 1024)
	for i := 0; i < 5; i++ {
		n, err := cConn.Write(buf)
		if err != nil {
			log.Fatalln(err)
		}

		fmt.Println("client: wrote: ", string(buf[0:n]))

		n, err = cConn.Read(echo)
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Println("echo bot send: ", string(echo[0:n]))

	}
	err = cConn.Close()
	if err != nil {
		log.Fatalln(err)
	}
	wg.Done()
}

func main() {
	sAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		log.Fatalln(err)
	}

	sConn, err := net.ListenUDP("udp", sAddr)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println("Listening on ", sConn.LocalAddr().String())
	wg := sync.WaitGroup{}
	wg.Add(1)
	go client(sConn.LocalAddr().(*net.UDPAddr), &wg)
	buf := make([]byte, 1024)
	for i := 0; i < 5; i++ {
		n, addr, err := sConn.ReadFromUDP(buf)
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Println("server read: ", string(buf[0:n]))
		time.Sleep(time.Second)
		n, err = sConn.WriteTo([]byte(string(buf[0:n])+" "+strconv.FormatInt(int64(i+1), 10)), addr)
		if err != nil {
			log.Fatalln(err)
		}
	}
	sConn.Close()
	wg.Wait()
}
