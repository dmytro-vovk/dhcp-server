package main

import (
	"config"
	"flag"
	"log"
	"server"
	"tcp_resolver"
)

var conf *config.ServerConfig

func init() {
	configFile := flag.String("config", "/etc/deep-dhcp/config.json", "Path to config file")
	flag.Parse()
	log.Print("Starting Deep DHCP Server...")
	var err error
	conf, err = config.Read(*configFile)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Config read from %s", *configFile)
}

func main() {
	log.Printf("Listening for DHCP requests on %s", conf.Listen)
	var resolver server.Resolver
	if conf.Resolver.Address != "" {
		log.Printf("Using tcp resolver at %q (max conns %d)", conf.Resolver.Address, conf.Resolver.Limit)
		var err error
		if resolver, err = tcp_resolver.New(conf.Resolver); err != nil {
			log.Fatalf("Error creating resolver: %s", err)
		}
	} else {
		log.Print("Using default resolver")
		resolver = server.NewDefaultResolver(conf)
	}
	server.
		New(conf).
		SetResolver(resolver).
		Run()
}
