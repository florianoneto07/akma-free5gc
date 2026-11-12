package context

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/free5gc/openapi/models"
)

// AefSecurityMethods returns the security methods that the API exposing
// function aefId published, in the order first seen: those of its AEF
// profiles and those of their interfaces (TS 29.222 table 8.2.4.2.4-1).
func (c *CCFContext) AefSecurityMethods(aefId string) []models.CapifSecurityMethod {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []models.CapifSecurityMethod
	add := func(ms []models.CapifSecurityMethod) {
		for _, m := range ms {
			if !slices.Contains(out, m) {
				out = append(out, m)
			}
		}
	}
	for _, api := range c.apis {
		for _, p := range api.Description.AefProfiles {
			if p.AefId != aefId {
				continue
			}
			add(p.SecurityMethods)
			for _, i := range p.InterfaceDescriptions {
				add(i.SecurityMethods)
			}
		}
	}
	return out
}

// AefByInterface returns the API exposing function that published an
// interface with the address and port of i.
func (c *CCFContext) AefByInterface(i models.CapifInterfaceDescription) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, api := range c.apis {
		for _, p := range api.Description.AefProfiles {
			for _, pi := range p.InterfaceDescriptions {
				if pi.Ipv4Addr == i.Ipv4Addr && pi.Ipv6Addr == i.Ipv6Addr && pi.Fqdn == i.Fqdn && pi.Port == i.Port {
					return p.AefId, true
				}
			}
		}
	}
	return "", false
}

// AefPublishes tells whether a service API named apiName is published with an
// AEF profile of aefId.
func (c *CCFContext) AefPublishes(aefId, apiName string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, api := range c.apis {
		if api.Description.ApiName != apiName {
			continue
		}
		for _, p := range api.Description.AefProfiles {
			if p.AefId == aefId {
				return true
			}
		}
	}
	return false
}

// Scope is an OAuth2 scope of CAPIF: the API names granted at each API
// exposing function.
type Scope map[string][]string

// ParseScope reads a scope in the format of TS 29.222 table 8.5.4.2.6-1 when
// neither CAPIF_Ext1 nor CAPIF_Ext2 is supported:
// "3gpp#aefId1:apiName1,apiName2;aefId2:apiName3". Additional space-delimited
// strings (NOTE 2 of the table) are not supported.
func ParseScope(s string) (Scope, error) {
	rest, ok := strings.CutPrefix(s, "3gpp#")
	if !ok {
		return nil, errors.New(`the scope shall start with "3gpp#"`)
	}
	if strings.ContainsAny(rest, " \t") {
		return nil, errors.New("additional scope strings are not supported")
	}
	scope := Scope{}
	for _, part := range strings.Split(rest, ";") {
		aef, apis, ok := strings.Cut(part, ":")
		if !ok || aef == "" || apis == "" {
			return nil, fmt.Errorf("%q is not \"aefId:apiName[,apiName]\"", part)
		}
		for _, api := range strings.Split(apis, ",") {
			if api == "" || strings.ContainsAny(api, "#:") {
				return nil, fmt.Errorf("invalid API name in %q", part)
			}
			if !slices.Contains(scope[aef], api) {
				scope[aef] = append(scope[aef], api)
			}
		}
	}
	return scope, nil
}

// String writes the scope in the format of ParseScope, with the AEFs and the
// API names in order.
func (s Scope) String() string {
	aefs := make([]string, 0, len(s))
	for aef := range s {
		aefs = append(aefs, aef)
	}
	slices.Sort(aefs)
	parts := make([]string, 0, len(aefs))
	for _, aef := range aefs {
		apis := slices.Clone(s[aef])
		slices.Sort(apis)
		parts = append(parts, aef+":"+strings.Join(apis, ","))
	}
	return "3gpp#" + strings.Join(parts, ";")
}
