// Command crl serves the certificate revocation lists of the lab over HTTP
// (TS 33.310 cl. 6.1a and 7.1): GET and HEAD of /<name>.crl, from the files of
// one directory. The peers fetch them through the CRL distribution point of
// the certificates, without TLS: the repository "shall be accessible without
// relying on a secure connection" (TS 33.310 cl. 7.1).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

type config struct {
	Configuration struct {
		BindingIPv4 string `yaml:"bindingIPv4"`
		Port        int    `yaml:"port"`
		Directory   string `yaml:"directory"`
	} `yaml:"configuration"`
}

func readConfig(path string) (*config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &config{}
	if err = yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c := cfg.Configuration
	if net.ParseIP(c.BindingIPv4) == nil || c.Port <= 0 || c.Port > 65535 || c.Directory == "" {
		return nil, fmt.Errorf("%s: bindingIPv4, port and directory are mandatory", path)
	}
	return cfg, nil
}

// logger writes to the console and, in the format of the free5GC log file, to
// the file of the -l option.
type logger struct {
	mu   sync.Mutex
	file io.Writer
}

func (l *logger) printf(level, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Printf("%s [%s][CRL] %s\n", now, level, msg)
	if l.file != nil {
		fmt.Fprintf(l.file, "time=%q level=%s msg=%q CAT=\"Main\" NF=\"CRL\"\n", now, level, msg)
	}
}

var crlName = regexp.MustCompile(`^/[A-Za-z0-9][A-Za-z0-9._-]*\.crl$`)

// handler serves the CRLs of dir. The DER form goes as application/pkix-crl
// (RFC 2585 cl. 4; RFC 5280 cl. 4.2.1.13).
func handler(dir string, log *logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !crlName.MatchString(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		f, err := os.Open(filepath.Join(dir, filepath.Base(r.URL.Path)))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close() //nolint:errcheck
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/pkix-crl")
		http.ServeContent(w, r, "", info.ModTime(), f)
		log.printf("debug", "%s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
	})
}

func run() error {
	cfgPath := flag.String("c", "config/crlcfg.yaml", "configuration file")
	logPath := flag.String("l", "", "log file")
	flag.Parse()

	log := &logger{}
	if *logPath != "" {
		f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		defer f.Close() //nolint:errcheck
		log.file = f
	}
	cfg, err := readConfig(*cfgPath)
	if err != nil {
		return err
	}

	c := cfg.Configuration
	addr := net.JoinHostPort(c.BindingIPv4, strconv.Itoa(c.Port))
	server := &http.Server{
		Addr:              addr,
		Handler:           handler(c.Directory, log),
		ReadHeaderTimeout: 5 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	log.printf("info", "Start CRL service (http, listen on %s)", addr)
	if err = server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	log.printf("info", "CRL service stopped")
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "crl:", err)
		os.Exit(1)
	}
}
