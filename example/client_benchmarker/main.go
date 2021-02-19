package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"golang.org/x/net/http2"

	"github.com/lucas-clemente/quic-go/h2quic"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

func main() {
	verbose := flag.Bool("v", false, "verbose")
	multipath := flag.Bool("m", false, "multipath")
	output := flag.String("o", "", "logging output")
	cache := flag.Bool("c", false, "cache handshake information")
	bindAddr := flag.String("b", "0.0.0.0", "bind address")
	pathScheduler := flag.String("ps", "LowLatency", "path scheduler")
	streamScheduler := flag.String("ss", "RoundRobin", "stream scheduler")
	flag.Parse()
	urls := flag.Args()

	if *verbose {
		utils.SetLogLevel(utils.LogLevelDebug)
	} else {
		utils.SetLogLevel(utils.LogLevelInfo)
	}

	if *output != "" {
		logfile, err := os.Create(*output)
		if err != nil {
			panic(err)
		}
		defer logfile.Close()
		log.SetOutput(logfile)
	}

	quicConfig := &quic.Config{
		CreatePaths:     *multipath,
		CacheHandshake:  *cache,
		BindAddr:        *bindAddr,
		PathScheduler:   *pathScheduler,
		StreamScheduler: *streamScheduler,
	}

	// Using modified http API (allows http priorities)
	hclient := &h2quic.Client{
		Transport: h2quic.RoundTripper{QuicConfig: quicConfig, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}

	// Using standard (unmodified) http API
	/*hclient := &http.Client{
		Transport: &h2quic.RoundTripper{QuicConfig: quicConfig, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}*/

	priority := &http2.PriorityParam{
		Weight:    0xff,
		StreamDep: 0x0,
		Exclusive: false,
	}

	var wg sync.WaitGroup
	wg.Add(len(urls))
	for _, addr := range urls {
		utils.Infof("GET %s", addr)
		go func(addr string) {
			start := time.Now()
			rsp, err := hclient.Get(addr, priority)
			if err != nil {

				panic(err)
			}

			// Test stuff
			u, err := url.Parse(addr)
			if err != nil {
				panic(err)
			}
			err = hclient.Transport.WritePriority(u.Hostname()+":"+u.Port(), 9, &http2.PriorityParam{})
			if err != nil {
				panic(err)
			}

			body := &bytes.Buffer{}
			_, err = io.Copy(body, rsp.Body)
			if err != nil {
				panic(err)
			}
			elapsed := strconv.FormatFloat(time.Since(start).Seconds(), 'f', -1, 64)
			utils.Infof("%s", elapsed)
			wg.Done()
		}(addr)
	}
	wg.Wait()
}
