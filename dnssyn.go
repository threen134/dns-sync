package main

import (
	"bytes"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	dnssvcsv1 "github.com/IBM/networking-go-sdk/dnssvcsv1"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

var dnsServicesURL string
var dnsServicesInstanceID string
var dnsServicesZoneID string
var syncInternal int
var zoneName string
var zonePath string
var restartCmd string
var listingIP string

var DEFAULT_TTL uint32 = 15 * 60 // default ttl is 15 minutes
var ONE_MIN uint32 = 60
var ONE_HOUR uint32 = 60 * ONE_MIN
var ONE_DAY uint32 = 24 * ONE_HOUR
var ONE_WEEK uint32 = 7 * ONE_DAY

func init() {
	var err error
	dnsServicesURL = os.Getenv("DNS_SVCS_URL")
	dnsServicesInstanceID = os.Getenv("DNS_SVCS_INSTANCE_ID")
	dnsServicesZoneID = os.Getenv("DNS_SVCS_ZONE_ID")
	zoneName = os.Getenv("BIND9_ZONE_NAME")
	zonePath = os.Getenv("BIND9_ZONE_PATH")
	restartCmd = os.Getenv("RESTART_CMD")
	listingIP = os.Getenv("LISTING_IP")
	syncInternal, err = strconv.Atoi(os.Getenv("DNS_SVCS_SYNC_INTERNAL"))
	if err != nil {
		log.Fatal("invalid DNS_SVCS_SYNC_INTERNAL format.")
	}

	lvl, ok := os.LookupEnv("LOG_LEVEL")
	// LOG_LEVEL not set, let's default to debug
	if !ok {
		lvl = "debug"
	}
	// parse string, this is built-in feature of logrus
	ll, err := log.ParseLevel(lvl)
	if err != nil {
		ll = log.DebugLevel
	}
	// set global log level
	log.SetLevel(ll)
	switch ll {
	case log.DebugLevel:
		core.SetLoggingLevel(core.LevelDebug)
	case log.InfoLevel:
		core.SetLoggingLevel(core.LevelInfo)
	default:
		core.SetLoggingLevel(core.LevelDebug)
	}
}

func main() {
	authenticator, err := core.GetAuthenticatorFromEnvironment("service")
	if err != nil {
		log.Error(err)
		log.Panic("fail to get auth information.")
	}

	options := &dnssvcsv1.DnsSvcsV1Options{Authenticator: authenticator}

	service, err := dnssvcsv1.NewDnsSvcsV1(options)
	if err != nil {
		log.Error(err)
		log.Fatal("failed to initial dns service.")
	}
	service.SetServiceURL(dnsServicesURL)

	// Construct an instance of the ExportResourceRecordsOptions model
	exportResourceRecordsOptionsModel := new(dnssvcsv1.ExportResourceRecordsOptions)
	exportResourceRecordsOptionsModel.InstanceID = core.StringPtr(dnsServicesInstanceID)
	exportResourceRecordsOptionsModel.DnszoneID = core.StringPtr(dnsServicesZoneID)

	var preHashVal uint32
	for {
		var result io.ReadCloser
		var response *core.DetailedResponse
		var err error

		for i := 0; i <= 3; i++ {
			result, response, err = service.ExportResourceRecords(exportResourceRecordsOptionsModel)
			if err == nil && response.StatusCode == http.StatusOK {
				break
			}
			time.Sleep(10 * time.Second)
		}
		if err != nil && response.StatusCode != http.StatusOK {
			log.Error(err)
			log.Fatal("fail to call pdns service")
		}

		log.Debug(response.StatusCode)
		log.Debug(result)
		dnszone, err := io.ReadAll(result)
		if err != nil {
			log.Error(err)
			log.Fatal("fail to read response body")
		}
		hashVal := hash(dnszone)
		if preHashVal != hashVal {
			preHashVal = hashVal
			saveZoneFile(dnszone, zoneName, zonePath)
			log.Info("update dns zone file")
			log.Info("restart dns service")
			resetDNSServer(restartCmd)
		} else {
			log.Info("PDNS zone file not change, skip sync")
		}
		log.Info(fmt.Sprintf("wait %d to next sync look", syncInternal))
		time.Sleep(time.Duration(syncInternal) * time.Second)
	}
}

func hash(s []byte) uint32 {
	h := fnv.New32a()
	h.Write(s)
	return h.Sum32()
}

func saveZoneFile(r []byte, zoneName, path string) {
	zoneParser := dns.NewZoneParser(bytes.NewReader(r), zoneName, "")
	zoneParser.SetDefaultTTL(DEFAULT_TTL)
	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   zoneName + ".",
			Ttl:    3 * ONE_WEEK,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
		},
		Ns:      zoneName + ".",
		Mbox:    "admin." + zoneName + ".",
		Serial:  0,
		Refresh: 12 * ONE_HOUR,
		Retry:   15 * ONE_MIN,
		Expire:  3 * ONE_WEEK,
		Minttl:  2 * ONE_HOUR,
	}

	localhost := &dns.A{
		Hdr: dns.RR_Header{
			Name:   zoneName + ".",
			Ttl:    DEFAULT_TTL,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
		},
		A: net.ParseIP(listingIP),
	}
	ns := &dns.NS{
		Hdr: dns.RR_Header{
			//	Name:   zoneName + ".",
			Rrtype: dns.TypeNS,
			Ttl:    DEFAULT_TTL,
			Class:  dns.ClassINET,
		},
		Ns: zoneName + ".",
	}

	dnsRRs := []dns.RR{soa, localhost, ns}

	// the $origin alias `@` will be transformed to origin domain, so no need to transform it by us
	for rr, ok := zoneParser.Next(); ok; rr, ok = zoneParser.Next() {
		log.Debug(rr.String())
		dnsRRs = append(dnsRRs, rr)
	}

	// bad zone file
	if err := zoneParser.Err(); err != nil {
		log.WithError(err).Error("Fail to parse zone file")
		log.Fatal("invalid pdns zone file")
	}
	writeFile(path, dnsRRs)
}

func writeFile(path string, rrs []dns.RR) {
	f, err := os.Create(path)
	defer f.Close()
	if err != nil {
		log.Error(err.Error())
		log.Fatal("fail to open file")
	}

	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypePTR {
			// skip PTR type RR
			continue
		}
		_, err := fmt.Fprintln(f, rr.String())
		if err != nil {
			log.Error(err.Error())
			log.Fatal("fail to write rr to file")
			return
		}
	}
	log.Info("file written successfully")
}

func resetDNSServer(cmdstr string) {
	cmdslice := strings.Split(cmdstr, " ")
	cmd := exec.Command(cmdslice[0], cmdslice[1:]...)
	output, err := cmd.CombinedOutput()
	log.Info(string(output))
	if err != nil {
		log.Error(err)
		log.Fatal("fail to restart dns servcie")
	}
}
