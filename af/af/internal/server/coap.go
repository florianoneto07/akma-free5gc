package server

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/florianoneto07/akma-free5gc/af/af/internal/logger"
	"github.com/florianoneto07/akma-free5gc/af/coap"
)

// CoAP answers a CoAP request authenticated with K_AF: on a DTLS
// association (TS 33.535 Annex C), or protected by OSCORE (Annex D), over is
// "PSK DTLS" or "OSCORE", for the log. A GET of the resource gets the
// Application Session Establishment Response (cl. 6.2.1 step 9), in JSON, as
// on the PSK TLS profiles. remote is the address of the UE, for the log.
func (s *Server) CoAP(req *coap.Message, sess PSKSession, remote, over string) *coap.Message {
	// Options this server understands; any other critical one is refused
	// (RFC 7252 cl. 5.4.1).
	if n, ok := req.UnknownCritical(coap.OptionURIHost, coap.OptionURIPath, coap.OptionURIPort,
		coap.OptionAccept); ok {
		logger.UaLog.Warnf("CoAP request from %s with the unknown critical option %d", remote, n)
		return coapError(coap.BadOption, CauseInvalidRequest)
	}
	// Uri-Host, when present, is the FQDN of the AF, as the Host header of
	// the HTTP profiles; its default is the IP address (RFC 7252
	// cl. 5.10.1), which the server_name of the handshake already named.
	if host, ok := req.Option(coap.OptionURIHost); ok && !strings.EqualFold(string(host), s.s.FQDN) {
		logger.UaLog.Warnf("CoAP request from %s for host %q, not %s", remote, host, s.s.FQDN)
		return coapError(coap.NotFound, CauseMisdirectedRequest)
	}
	if req.Path() != s.s.Path {
		return coapError(coap.NotFound, CauseNotFound)
	}
	if req.Code != coap.GET {
		return coapError(coap.MethodNotAllowed, CauseMethodNotAllowed)
	}
	if !s.now().Before(sess.KafExpiry) {
		logger.UaLog.Infof("K_AF for A-KID %s expired at %s: request rejected", sess.AKid,
			sess.KafExpiry.UTC().Format(time.RFC3339))
		return coapError(coap.Forbidden, CauseKafExpired)
	}
	body, _ := json.Marshal(SessionResponse{AKid: sess.AKid, KafExpiry: sess.KafExpiry.UTC()})
	logger.UaLog.Infof("UE with A-KID %s served over %s (AF_ID %s)", sess.AKid, over, sess.AfID.Transport())
	rsp := &coap.Message{Code: coap.Content, Payload: body}
	rsp.Add(coap.OptionContentFormat, coap.EncodeUint(uint32(coap.FormatJSON)))
	return rsp
}

// coapError is an error response with the cause in JSON, as the HTTP
// profiles send it.
func coapError(code coap.Code, cause string) *coap.Message {
	body, _ := json.Marshal(ErrorResponse{Cause: cause})
	rsp := &coap.Message{Code: code, Payload: body}
	rsp.Add(coap.OptionContentFormat, coap.EncodeUint(uint32(coap.FormatJSON)))
	return rsp
}
