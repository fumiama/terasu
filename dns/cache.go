package dns

import (
	"context"
	"time"

	"github.com/FloatTech/ttl"
	"github.com/fumiama/terasu/ip"
)

var lookupTable = ttl.NewCache[string, []string](time.Hour)

// LookupHost use default resolver with its fallback
func LookupHost(ctx context.Context, host string) (addrs []string, err error) {
	addrs = lookupTable.Get(host)
	if len(addrs) == 0 {
		addrs, err = DefaultResolver.LookupHost(ctx, host)
		if err != nil {
			if ip.IsIPv6Available {
				addrs, err = IPv6Servers.lookupHostDoH(ctx, host)
			} else {
				addrs, err = IPv4Servers.lookupHostDoH(ctx, host)
			}
			if err != nil {
				return nil, err
			}
		}
		lookupTable.Set(host, addrs)
	}
	return
}
