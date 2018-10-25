package main

// Compile for i386: GOARCH=386 CGO_ENABLED=1 go build src/dhcps.go
import (
	"flag"
	"log"

	"github.com/dmitry-vovk/dhcp-server/src/config"
	"github.com/dmitry-vovk/dhcp-server/src/server"
)

var conf *config.ServerConfig

func init() {
	configFile := flag.String("config", "/etc/deep-dhcp/config.json", "Path to config file")
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Print("Starting Deep DHCP Server...")
	var err error
	conf, err = config.Read(*configFile)
	if err != nil {
		log.Fatalf("Error reading config file: %s", err)
	}
	log.Printf("Config read from %s", *configFile)
	log.Printf("Will serve %d clients", len(conf.Leases)+len(conf.VLans))
}

func main() {
	log.Printf("Listening for DHCP requests on %s", conf.Listen)
	server.New(conf).Run()
}
