package dnscache

import (
	"encoding/json"
	"errors"
)

var ErrDataNotFound = errors.New("requested data was not found")
var ErrKeyNotSupported = errors.New("queried key is not supported")

type DNSDatasource struct {
	dns *DNSCache
}

func NewDataSource(d *DNSCache) *DNSDatasource {
	return &DNSDatasource{
		dns: d,
	}
}

func (ctx DNSDatasource) Get(key interface{}) (map[string]interface{}, error) {
	keyString, ok := key.(string)
	if !ok {
		return nil, ErrKeyNotSupported
	}

	query, err := ctx.dns.Get(keyString)

	if errors.Is(err, ErrDNSRecordNotFound) {
		return nil, ErrDataNotFound
	}

	if errors.Is(err, ErrDNSRecordNotFound) {
		return nil, ErrDataNotFound
	}

	if len(query.dnsResults) == 0 && len(query.ipResults) == 0 {
		return nil, ErrDataNotFound
	}

	dnsRoot := ""
	if len(query.dnsResults) > 0 {
		dnsRoot = query.dnsResults[0]
	}

	result := map[string]interface {
	}{
		"ip_addresses": query.ipResults,
		"dns_queries":  query.dnsResults,
		"dns_root":     dnsRoot,
	}

	return result, nil
}

func (ctx DNSDatasource) Keys() []string {
	return []string{"string"}
}

func (ctx DNSDatasource) Schema() string {
	schemaMap := map[string]string{
		"ip_addresses": "[]string",
		"dns_queries":  "[]string",
		"dns_root":     "string",
	}
	schema, _ := json.Marshal(schemaMap)
	return string(schema)
}

func (ctx DNSDatasource) Version() uint {
	return 1
}

func (ctx DNSDatasource) Namespace() string {
	return "tracee"
}

func (ctx DNSDatasource) ID() string {
	return "dns"
}
