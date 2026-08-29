package blobstore

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

type S3Config struct {
	Endpoint     string
	Region       string
	Bucket       string
	AccessKey    string
	SecretKey    string
	SessionToken string
	Prefix       string
	TempDir      string
	AllowHTTP    bool
	Client       *http.Client
}

type S3Store struct {
	endpoint     *url.URL
	region       string
	bucket       string
	accessKey    string
	secretKey    string
	sessionToken string
	prefix       string
	tempDir      string
	client       *http.Client
}

func NewS3(cfg S3Config) (*S3Store, error) {
	endpoint, err := url.Parse(strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/"))
	if err != nil || endpoint.Host == "" || (endpoint.Scheme != "https" && endpoint.Scheme != "http") {
		return nil, errors.New("S3 endpoint must be an absolute HTTP(S) URL")
	}
	if endpoint.Scheme == "http" && !cfg.AllowHTTP && !isLoopbackHost(endpoint.Hostname()) {
		return nil, errors.New("S3 endpoint must use HTTPS unless insecure HTTP is explicitly enabled")
	}
	if strings.TrimSpace(cfg.Bucket) == "" || strings.ContainsAny(cfg.Bucket, "/\\") {
		return nil, errors.New("S3 bucket is required and must not contain slashes")
	}
	if strings.TrimSpace(cfg.AccessKey) == "" || cfg.SecretKey == "" {
		return nil, errors.New("S3 access key and secret key are required")
	}
	if prefix := cleanPrefix(cfg.Prefix); prefix != "" && !validKey(prefix) {
		return nil, errors.New("S3 prefix is invalid")
	}
	region := strings.TrimSpace(cfg.Region)
	if region == "" {
		region = "us-east-1"
	}
	tempDir := strings.TrimSpace(cfg.TempDir)
	if tempDir == "" {
		tempDir = os.TempDir()
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          16,
			MaxIdleConnsPerHost:   8,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		}}
	}
	return &S3Store{
		endpoint: endpoint, region: region, bucket: strings.TrimSpace(cfg.Bucket),
		accessKey: strings.TrimSpace(cfg.AccessKey), secretKey: cfg.SecretKey,
		sessionToken: strings.TrimSpace(cfg.SessionToken), prefix: cleanPrefix(cfg.Prefix),
		tempDir: tempDir, client: client,
	}, nil
}

func (s *S3Store) Put(reader io.Reader, limit int64) (Result, error) {
	if limit <= 0 || limit > MaxBlobBytes {
		limit = MaxBlobBytes
	}
	temporary, err := os.CreateTemp(s.tempDir, ".barktrace-s3-*")
	if err != nil {
		return Result{}, err
	}
	name := temporary.Name()
	defer os.Remove(name)
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(temporary, hash), io.LimitReader(reader, limit+1))
	if err != nil {
		temporary.Close()
		return Result{}, err
	}
	if written > limit {
		temporary.Close()
		return Result{}, errors.New("blob exceeds size limit")
	}
	if _, err := temporary.Seek(0, io.SeekStart); err != nil {
		temporary.Close()
		return Result{}, err
	}
	checksum := hex.EncodeToString(hash.Sum(nil))
	key := checksum[:2] + "/" + checksum[2:4] + "/" + checksum
	request, err := s.request(http.MethodPut, key, temporary, written, checksum)
	if err != nil {
		temporary.Close()
		return Result{}, err
	}
	response, err := s.client.Do(request)
	temporary.Close()
	if err != nil {
		return Result{}, err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return Result{}, fmt.Errorf("S3 PUT returned HTTP %d", response.StatusCode)
	}
	return Result{Key: key, Checksum: checksum, Size: written}, nil
}

func (s *S3Store) Open(key string) (Reader, error) {
	if !validKey(key) {
		return nil, errors.New("invalid blob key")
	}
	emptyHash := sha256.Sum256(nil)
	request, err := s.request(http.MethodGet, key, nil, 0, hex.EncodeToString(emptyHash[:]))
	if err != nil {
		return nil, err
	}
	response, err := s.client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		return nil, fmt.Errorf("S3 GET returned HTTP %d", response.StatusCode)
	}
	temporary, err := os.CreateTemp(s.tempDir, ".barktrace-s3-read-*")
	if err != nil {
		response.Body.Close()
		return nil, err
	}
	name := temporary.Name()
	written, copyErr := io.Copy(temporary, io.LimitReader(response.Body, MaxBlobBytes+1))
	closeErr := response.Body.Close()
	if copyErr != nil || closeErr != nil || written > MaxBlobBytes {
		temporary.Close()
		os.Remove(name)
		if copyErr != nil {
			return nil, copyErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		return nil, errors.New("S3 object exceeds blob limit")
	}
	if _, err := temporary.Seek(0, io.SeekStart); err != nil {
		temporary.Close()
		os.Remove(name)
		return nil, err
	}
	return &temporaryReader{File: temporary, name: name}, nil
}

type temporaryReader struct {
	*os.File
	name string
}

func (r *temporaryReader) Close() error {
	err := r.File.Close()
	removeErr := os.Remove(r.name)
	if err != nil {
		return err
	}
	if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		return removeErr
	}
	return nil
}

func (s *S3Store) Remove(key string) error {
	if !validKey(key) {
		return errors.New("invalid blob key")
	}
	emptyHash := sha256.Sum256(nil)
	request, err := s.request(http.MethodDelete, key, nil, 0, hex.EncodeToString(emptyHash[:]))
	if err != nil {
		return err
	}
	response, err := s.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode != http.StatusNotFound && (response.StatusCode < 200 || response.StatusCode >= 300) {
		return fmt.Errorf("S3 DELETE returned HTTP %d", response.StatusCode)
	}
	return nil
}

func (s *S3Store) request(method, key string, body io.Reader, size int64, payloadHash string) (*http.Request, error) {
	objectPath := path.Join(s.endpoint.Path, s.bucket, s.prefix, key)
	endpoint := *s.endpoint
	endpoint.Path = "/" + strings.TrimPrefix(objectPath, "/")
	request, err := http.NewRequest(method, endpoint.String(), body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		request.ContentLength = size
	}
	now := time.Now().UTC()
	request.Header.Set("X-Amz-Date", now.Format("20060102T150405Z"))
	request.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if s.sessionToken != "" {
		request.Header.Set("X-Amz-Security-Token", s.sessionToken)
	}
	s.sign(request, payloadHash, now)
	return request, nil
}

func (s *S3Store) sign(request *http.Request, payloadHash string, now time.Time) {
	date := now.Format("20060102")
	canonicalHeaders := "host:" + request.URL.Host + "\n" +
		"x-amz-content-sha256:" + payloadHash + "\n" +
		"x-amz-date:" + now.Format("20060102T150405Z") + "\n"
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	if s.sessionToken != "" {
		canonicalHeaders += "x-amz-security-token:" + s.sessionToken + "\n"
		signedHeaders += ";x-amz-security-token"
	}
	canonicalRequest := strings.Join([]string{request.Method, request.URL.EscapedPath(), request.URL.Query().Encode(), canonicalHeaders, signedHeaders, payloadHash}, "\n")
	scope := date + "/" + s.region + "/s3/aws4_request"
	digest := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := "AWS4-HMAC-SHA256\n" + now.Format("20060102T150405Z") + "\n" + scope + "\n" + hex.EncodeToString(digest[:])
	dateKey := hmacSHA256([]byte("AWS4"+s.secretKey), date)
	regionKey := hmacSHA256(dateKey, s.region)
	serviceKey := hmacSHA256(regionKey, "s3")
	signingKey := hmacSHA256(serviceKey, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))
	request.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+s.accessKey+"/"+scope+", SignedHeaders="+signedHeaders+", Signature="+signature)
}

func hmacSHA256(key []byte, value string) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(value))
	return h.Sum(nil)
}

func cleanPrefix(value string) string {
	return strings.Trim(strings.TrimSpace(value), "/")
}

func validKey(key string) bool {
	key = strings.TrimSpace(key)
	return key != "" && !strings.HasPrefix(key, "/") && !strings.Contains(key, "..") && !strings.Contains(key, "\\")
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
