package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	domain := flag.String("d", "", "A domain to check ssl cert validity.\nEg: maheshrjl.com")
	flag.Parse()

	checkDom := *domain
	if checkDom == "" {
		fmt.Println("Could not find a valid domain! \nEg: -d maeshrjl.com")
		os.Exit(1)
	}

	println("Checking certificate for domain:", *domain)

	conn, err := tls.Dial("tcp", *domain+":443", nil)
	if err != nil {
		panic("Server doesn't support SSL certificate!\n Err:" + err.Error())
	}

	err = conn.VerifyHostname(*domain)
	if err != nil {
		panic("Hostname doesn't match with certificate: " + err.Error())
	}

	expiry := conn.ConnectionState().PeerCertificates[0].NotAfter
	fmt.Printf("Issuer: %s\nExpiry: %v\n", conn.ConnectionState().PeerCertificates[0].Issuer, expiry.Format(time.RFC850))
}
