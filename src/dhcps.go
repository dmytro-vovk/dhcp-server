package main

import (
	"config"
	"log"
	"server"
)

var conf *config.ServerConfig

func init() {
	log.Print("Starting Deep DHCP Server...")
	var err error
	configFile := "../conf/config.json"
	conf, err = config.Read(configFile)
	if err != nil {
		panic(err)
	}
	log.Printf("Config read from %s", configFile)
}

func main() {
	log.Printf("Listening for DHCP requests on %s", conf.Listen)
	server.New(conf).Run()
}
