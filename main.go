package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type Urls struct {
	Urls []string `yaml:"urls"`
}

type host struct {
	url      string
	hostname string
	scheme   string
	ipaddrs  []string
}

func handlePanic() {
	// detect if panic occurs or not
	a := recover()

	if a != nil {
		fmt.Println("RECOVER", a)
	}
}

func days(t time.Time) int {
	return int(math.Round(time.Since(t).Hours() / 24))
}

func ssl_days(host host, ip string) (int, error) {
	defer handlePanic()
	addr := fmt.Sprintf("[%v]:443", ip)
	var cfg tls.Config
	cfg.ServerName = host.hostname
	cfg.InsecureSkipVerify = true
	conn, err := tls.Dial("tcp", addr, &cfg)
	if err != nil {
		panic(err)
	}
	conn.Handshake()
	certs := conn.ConnectionState().PeerCertificates

	return -days(certs[0].NotAfter), nil
}

func parse_url(val string) host {
	defer handlePanic()
	u, err := url.Parse(val)
	if err != nil {
		panic(err)
	}
	var host host

	if u.Scheme == "" {
		host.url = fmt.Sprintf("https://%v", val)
		host.scheme = "https"
		u, _ = url.Parse(host.url)
	} else {
		host.url = val
		host.scheme = u.Scheme
	}

	host.hostname = u.Host

	ips, err := net.LookupIP(host.hostname)
	if err == nil {
		for _, ip := range ips {
			host.ipaddrs = append(host.ipaddrs, ip.String())
		}
	}

	return host
}

func get_host_and_ssl(wg *sync.WaitGroup, uri string, ip string, host host) {
	defer handlePanic()
	defer wg.Done()

	// transfor the request URL from hostname to [ip]
	u, _ := url.Parse(host.url)
	u.Host = fmt.Sprintf("[%v]", ip)

	// SNI handling, because we call the host by IP not hostname
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName: host.hostname,
		},
	}

	client := http.Client{
		Timeout: 15 * time.Second,

		// don't follow redirects
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: tr,
	}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		panic(err)
	}
	req.URL.Host = host.hostname
	req.URL.Scheme = host.scheme
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	if host.scheme == "https" {
		ssldays, err := ssl_days(host, ip)
		if err != nil {
			panic(err)
		}
		fmt.Printf("Host: %v \tIP: %v\tCode: %v\tSSL: %v\n", uri, ip, resp.StatusCode, ssldays)
	} else {
		fmt.Printf("Host: %v \tIP: %v\tCode: %v\n", uri, ip, resp.StatusCode)
	}
}

func main() {
	data, err := os.ReadFile("urls.yaml")
	if err != nil {
		panic(err)
	}

	var urls Urls

	if err := yaml.Unmarshal(data, &urls); err != nil {
		panic(err)
	}

	urlrequests := new(sync.WaitGroup)

	for _, uri := range urls.Urls {
		defer handlePanic()
		urlrequests.Add(1)

		go func() {
			defer urlrequests.Done()
			host := parse_url(uri)
			if len(host.ipaddrs) == 0 {
				log.Printf("Could not resolve %v", host.hostname)
			}

			iprequest := new(sync.WaitGroup)

			for _, ip := range host.ipaddrs {
				iprequest.Add(1)
				go get_host_and_ssl(iprequest, uri, ip, host)
			}
			iprequest.Wait()
		}()
	}

	urlrequests.Wait()
}
