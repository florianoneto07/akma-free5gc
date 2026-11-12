package context

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/florianoneto07/akma-free5gc/free5gc/ccf/internal/logger"
)

const (
	// crlValidity is the time between thisUpdate and nextUpdate.
	crlValidity = 7 * 24 * time.Hour
	// crlRenewBefore: the CRL is signed again this long before its nextUpdate.
	crlRenewBefore = 24 * time.Hour
	// crlCheckInterval is how often the CCF looks at the nextUpdate.
	crlCheckInterval = time.Hour
	// crlReasonCessation is cessationOfOperation (RFC 5280 cl. 5.3.1): the
	// API invoker offboarded.
	crlReasonCessation = 5
)

// loadCrl takes the revoked certificates and the number of the CRL of a
// previous run: the context of the CCF is in memory, and a revocation is not.
func (c *CCFContext) loadCrl(path string) error {
	der, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	list, err := x509.ParseRevocationList(der)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if err = list.CheckSignatureFrom(c.caCert); err != nil {
		logger.CapifLog.Warnf("CRL %s of another CA set aside: %v", path, err)
		return nil
	}
	c.crlEntries, c.crlNumber = list.RevokedCertificateEntries, list.Number
	return nil
}

// signCrl signs the CRL of the CA of the CCF, version 2 (TS 33.310 cl. 6.1a),
// and writes it where the service of the CRLs serves it. c.mu is held.
func (c *CCFContext) signCrl() error {
	path := c.cfg.Configuration.Ca.CrlFile
	if path == "" {
		return nil
	}
	now := c.Now()
	number := big.NewInt(1)
	if c.crlNumber != nil {
		number.Add(c.crlNumber, big.NewInt(1))
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    number,
		ThisUpdate:                now.Add(-time.Minute),
		NextUpdate:                now.Add(crlValidity),
		RevokedCertificateEntries: c.crlEntries,
	}, c.caCert, c.caKey)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	// The service of the CRLs never reads half a file.
	tmp := path + ".new"
	if err = os.WriteFile(tmp, der, 0o644); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	c.crlNumber, c.crlNext = number, now.Add(crlValidity)
	logger.CapifLog.Infof("CRL %s signed: %d revoked", path, len(c.crlEntries))
	return nil
}

// revoke adds a certificate to the CRL and signs it. c.mu is held.
func (c *CCFContext) revoke(serial *big.Int) {
	c.crlEntries = append(c.crlEntries, x509.RevocationListEntry{
		SerialNumber: serial, RevocationTime: c.Now(), ReasonCode: crlReasonCessation,
	})
	if err := c.signCrl(); err != nil {
		logger.CapifLog.Errorf("CRL not signed: %v", err)
	}
}

// Revoked reports whether a certificate of the CA of the CCF is in the CRL.
func (c *CCFContext) Revoked(serial *big.Int) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for i := range c.crlEntries {
		if c.crlEntries[i].SerialNumber.Cmp(serial) == 0 {
			return true
		}
	}
	return false
}

// RunCrl signs the CRL again before its nextUpdate, until ctx ends.
func (c *CCFContext) RunCrl(ctx context.Context) {
	ticker := time.NewTicker(crlCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.renewCrl()
		}
	}
}

// renewCrl signs the CRL when its nextUpdate is near.
func (c *CCFContext) renewCrl() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Now().Before(c.crlNext.Add(-crlRenewBefore)) {
		return
	}
	if err := c.signCrl(); err != nil {
		logger.CapifLog.Errorf("CRL not signed: %v", err)
	}
}
