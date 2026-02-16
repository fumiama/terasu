package doh

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/http2"

	"github.com/fumiama/terasu/ip"
	"github.com/fumiama/terasu/tls"
)

// RecordType ...
type RecordType uint16

const (
	RecordTypeNone RecordType = 0  // RecordTypeNone ...
	RecordTypeA    RecordType = 1  // RecordTypeA IPv4
	RecordTypeAAAA RecordType = 28 // RecordTypeAAAA IPv6
)

// Response represents the JSON response structure for DNS over HTTPS (DoH) queries.
// It contains DNS query results and metadata about the response.
type Response struct {
	// Status indicates the DNS query status code (0 = NOERROR, etc.)
	Status uint32
	// TC indicates whether the response was truncated (true if truncated)
	TC bool
	// RD indicates whether recursion was requested in the query
	RD bool
	// RA indicates whether the server supports recursion
	RA bool
	// AD indicates whether the response was authenticated (DNSSEC)
	AD bool
	// CD indicates whether the client requested that DNSSEC validation be disabled
	CD bool
	// Question contains the DNS query question section with name and type
	Question []struct {
		// Name is the domain name being queried
		Name string `json:"name"`
		// Type is the DNS record type being requested (A, AAAA, etc.)
		Type RecordType `json:"type"`
	}
	// Answer contains the DNS response answer section with resource records
	Answer []struct {
		// Name is the domain name for this resource record
		Name string `json:"name"`
		// Type is the DNS record type (A, AAAA, etc.)
		Type RecordType `json:"type"`
		// TTL is the time-to-live value for this resource record in seconds
		TTL uint16
		// Data is the textual representation of the resource record data
		Data string `json:"data"`
	}
	// EdnsClientSubnet is the EDNS client subnet information for geolocation
	EdnsClientSubnet string `json:"edns_client_subnet"`
	// Comment is an optional comment field for additional information
	Comment string
}

func (jr *Response) Hosts() []string {
	if len(jr.Answer) == 0 {
		return nil
	}
	hosts := make([]string, 0, len(jr.Answer))
	for _, ans := range jr.Answer {
		if ans.Type == RecordTypeA || ans.Type == RecordTypeAAAA {
			hosts = append(hosts, ans.Data)
		}
	}
	return hosts
}

var trsHTTP2ClientWithSystemDNS = http.Client{
	Transport: &http2.Transport{
		DialTLSContext: tls.DialTLSContextWithConfigAndSystemResolver,
	},
}

// LookupDoH lookup uname's ip from server
func LookupDoH(ctx context.Context, server, name string) (jr Response, err error) {
	jr, err = LookupDoHWithType(ctx, server, name, prefertyp())
	if err == nil {
		return
	}
	if ip.IsIPv6Available {
		jr, err = LookupDoHWithType(ctx, server, name, RecordTypeA)
	}
	return
}

// LookupDoHWithType ...
func LookupDoHWithType(ctx context.Context, server, name string, typ RecordType) (jr Response, err error) {
	sb := strings.Builder{}
	sb.WriteString(server)
	sb.WriteString("?name=")
	sb.WriteString(url.QueryEscape(name))
	if typ != RecordTypeNone {
		sb.WriteString("&type=")
		sb.WriteString(strconv.Itoa(int(typ)))
	}
	req, err := http.NewRequestWithContext(ctx, "GET", sb.String(), nil)
	if err != nil {
		return
	}
	req.Header.Add("accept", "application/dns-json")
	resp, err := trsHTTP2ClientWithSystemDNS.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&jr)
	if err != nil {
		return
	}
	if jr.Status != 0 {
		err = errors.New("comment: " + jr.Comment)
	}
	return
}

func prefertyp() RecordType {
	if ip.IsIPv6Available {
		return RecordTypeAAAA
	}
	return RecordTypeA
}
