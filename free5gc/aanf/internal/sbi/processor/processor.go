package processor

import (
	"regexp"

	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/pkg/app"
)

type ProcessorAanf interface {
	app.App
}

// Processor implements the Naanf_AKMA service operations.
type Processor struct {
	ProcessorAanf
}

func NewProcessor(aanf ProcessorAanf) (*Processor, error) {
	return &Processor{ProcessorAanf: aanf}, nil
}

// supportedFeatures is the SupportedFeatures of this AAnF: none of the
// optional features of TS 29.535 table 5.1.8-1 (AKMA_GPSI_Support,
// RoamingRestriction) is supported.
const supportedFeatures = "0"

// suppFeatPattern is the SupportedFeatures pattern of TS 29.571.
var suppFeatPattern = regexp.MustCompile(`^[A-Fa-f0-9]*$`)

// negotiatedFeatures returns the features supported by both sides when the
// consumer asked for feature negotiation (TS 29.500 cl. 6.6.2), or "" when
// it did not. As the AAnF supports no optional feature, the intersection is
// always empty.
func negotiatedFeatures(requested string) string {
	if requested == "" {
		return ""
	}
	return supportedFeatures
}
