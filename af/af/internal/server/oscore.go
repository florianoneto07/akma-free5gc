package server

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"

	"github.com/florianoneto07/akma-free5gc/af/af/internal/aanf"
	"github.com/florianoneto07/akma-free5gc/af/af/internal/logger"
	"github.com/florianoneto07/akma-free5gc/af/akmaoscore"
	"github.com/florianoneto07/akma-free5gc/af/akmatls"
	"github.com/florianoneto07/akma-free5gc/af/coap"
	"github.com/florianoneto07/akma-free5gc/af/oscore"
	"github.com/florianoneto07/akma-free5gc/shared/akma/afid"
)

// Causes of the AKMA resource of the OSCORE profile, beside those of the
// other profiles.
const (
	CauseOSCInputNotSupported = "OSC_INP_NOT_SUPPORTED"
	CauseUnsupportedFormat    = "UNSUPPORTED_CONTENT_FORMAT"
	CauseOSCORERequired       = "OSCORE_REQUIRED"
)

// OSCOREStore keeps the security contexts of the OSCORE profile.
type OSCOREStore interface {
	InUse(recipientID []byte) bool
	Add(*oscore.Entry) error
}

// AKMA answers the Application Session Establishment Request of the OSCORE
// profile, a POST of the AKMA resource (TS 33.535 D.3.2): it asks the AAnF
// for the K_AF of the A-KID of the request (steps 2 to 4), derives the
// security context (D.3.3), keeps it in store, pending until a request
// verifies with it, and answers 2.01 Created with N2 and UE-SID (step 3).
// Errors carry the cause as a diagnostic payload (RFC 7252 cl. 5.5.2).
// remote is the address of the UE, for the log.
func (s *Server) AKMA(req *coap.Message, store OSCOREStore, remote string) *coap.Message {
	if n, ok := req.UnknownCritical(coap.OptionURIHost, coap.OptionURIPath, coap.OptionURIPort,
		coap.OptionContentFormat, coap.OptionAccept); ok {
		logger.UaLog.Warnf("AKMA request from %s with the unknown critical option %d", remote, n)
		return diagnostic(coap.BadOption, CauseInvalidRequest)
	}
	if host, ok := req.Option(coap.OptionURIHost); ok && !strings.EqualFold(string(host), s.s.FQDN) {
		logger.UaLog.Warnf("AKMA request from %s for host %q, not %s", remote, host, s.s.FQDN)
		return diagnostic(coap.NotFound, CauseMisdirectedRequest)
	}
	if req.Code != coap.POST {
		return diagnostic(coap.MethodNotAllowed, CauseMethodNotAllowed)
	}
	if f, ok := req.ContentFormat(); !ok || f != coap.FormatCBOR {
		return diagnostic(coap.UnsupportedFormat, CauseUnsupportedFormat)
	}
	r, err := akmaoscore.ParseRequest(req.Payload, s.akid)
	switch {
	case errors.Is(err, akmaoscore.ErrOSCInput):
		logger.UaLog.Warnf("AKMA request from %s: %v", remote, err)
		return diagnostic(coap.BadRequest, CauseOSCInputNotSupported)
	case err != nil:
		logger.UaLog.Warnf("AKMA request from %s: %v", remote, err)
		return diagnostic(coap.BadRequest, CauseInvalidRequest)
	}

	id := afid.AfID{FQDN: s.s.FQDN, Protocol: akmatls.UaStarOSCORE}
	sess, kaf, err := s.ApplicationKey(context.Background(), id, r.AKID, remote)
	switch {
	case errors.Is(err, aanf.ErrKeyNotAvailable):
		logger.UaLog.Infof("No K_AKMA at the AAnF for A-KID %s (AF_ID %s): OSCORE context refused", r.AKID,
			id.Transport())
		return diagnostic(coap.Forbidden, CauseAkmaKeyNotAvailable)
	case errors.Is(err, ErrKafExpired):
		return diagnostic(coap.Forbidden, CauseKafExpired)
	case err != nil:
		return diagnostic(coap.ServiceUnavailable, CauseAanfUnavailable)
	}

	for range 8 {
		ueSID, n2 := make([]byte, akmaoscore.SenderIDSize), make([]byte, akmaoscore.NonceSize)
		_, _ = rand.Read(ueSID)
		_, _ = rand.Read(n2)
		// UE-SID differs from AF-SID, or both directions would share the key
		// and the nonces, and from the UE-SID of every other context, by
		// which the AF finds the context of a request (RFC 8613 cl. 3.3).
		if string(ueSID) == string(r.AFSID) || store.InUse(ueSID) {
			continue
		}
		payload := akmaoscore.Response{N2: n2, UESID: ueSID}.Marshal()
		c, err := akmaoscore.Context(kaf, req.Payload, payload, r.AFSID, ueSID, false)
		if err != nil {
			logger.UaLog.Errorf("OSCORE context for A-KID %s: %v", r.AKID, err)
			return diagnostic(coap.InternalServerError, CauseInvalidRequest)
		}
		// Expiry on the clock of the process, not on a shifted one.
		err = store.Add(&oscore.Entry{Context: c, Group: r.AKID, Expiry: sess.KafExpiry.Add(-s.s.ClockOffset),
			Data: sess})
		switch {
		case errors.Is(err, oscore.ErrIDInUse):
			continue
		case err != nil:
			logger.UaLog.Warnf("OSCORE context for A-KID %s from %s not kept: %v", r.AKID, remote, err)
			return diagnostic(coap.ServiceUnavailable, CauseInvalidRequest)
		}
		logger.UaLog.Infof("OSCORE context for %s with %s: UE-SID %x, AF-SID %x", sess, remote, ueSID, r.AFSID)
		rsp := &coap.Message{Code: coap.Created, Payload: payload}
		rsp.Add(coap.OptionContentFormat, coap.EncodeUint(uint32(coap.FormatCBOR)))
		return rsp
	}
	return diagnostic(coap.ServiceUnavailable, CauseInvalidRequest)
}

// diagnostic is an error response with the cause as diagnostic payload.
func diagnostic(code coap.Code, cause string) *coap.Message {
	return &coap.Message{Code: code, Payload: []byte(cause)}
}
