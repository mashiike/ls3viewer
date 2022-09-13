package ls3viewer

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"runtime"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/thanhpk/randstr"
	"golang.org/x/oauth2"
)

//go:embed index.html.tpl
var defaultHTMLTemplate string

type S3Client interface {
	manager.DownloadAPIClient
	ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
}

type LoggerFunc func(level string, v ...interface{})

type Options struct {
	HTMLTemplate string
	S3Client     S3Client
	Logger       LoggerFunc
	BaseURL      string
	Middleware   []func(http.Handler) http.Handler
}

func newOptions() *Options {
	return &Options{
		HTMLTemplate: defaultHTMLTemplate,
		Logger: func(level string, v ...interface{}) {
			vals := append([]interface{}{"[" + level + "]"}, v...)
			log.Println(vals...)
		},
	}
}

func (opts *Options) buildOptions() error {
	if opts.S3Client != nil {
		return nil
	}
	awsCfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return err
	}
	if opts.S3Client == nil {
		opts.S3Client = s3.NewFromConfig(awsCfg)
	}
	return nil
}

func (opts *Options) getBaseURL(r *http.Request) (*url.URL, error) {
	if opts.BaseURL != "" {
		return url.Parse(opts.BaseURL)
	}
	if r.URL.Scheme == "" {
		r.URL.Scheme = "https"
	}
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}
	u := &url.URL{
		Scheme: r.URL.Scheme,
		Host:   r.URL.Host,
	}
	return u, nil
}

func WithBaseURL(baseURL string) func(*Options) {
	return func(o *Options) {
		o.BaseURL = baseURL
	}
}

func WithBasicAuth(user, pass string) func(*Options) {
	return func(o *Options) {
		o.Middleware = append(o.Middleware, func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				clientID, clientSecret, ok := r.BasicAuth()
				if !ok || clientID != user || clientSecret != pass {
					w.Header().Add("WWW-Authenticate", `Basic realm="SECRET AREA"`)
					http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
					return
				}
				next.ServeHTTP(w, r)
			})
		})
	}
}

func WithGoogleOIDC(clientID string, clientSecret string, sessionEncryptKey []byte) func(*Options) {
	return func(o *Options) {
		o.Middleware = append(o.Middleware, func(next http.Handler) http.Handler {
			return &googleOIDCHandler{
				clientID:          clientID,
				clientSecret:      clientSecret,
				sessionEncryptKey: sessionEncryptKey,
				next:              next,
				opts:              o,
			}
		})
	}
}

type googleODICSession struct {
	IDToken    string `json:"id_token,omitempty"`
	RedirectTo string `json:"redirect_to,omitempty"`
	S          string `json:"s,omitempty"`
}

func (s *googleODICSession) UnmarshalCookie(r *http.Request, sessionEncryptKey []byte) error {
	sessionStr, err := r.Cookie("ls3viewer-session")
	if err != nil {
		return fmt.Errorf("cookie: %w", err)
	}
	cipherText, err := base64.RawStdEncoding.DecodeString(sessionStr.Value)
	if err != nil {
		return fmt.Errorf("decodeString: %w", err)
	}

	block, err := aes.NewCipher(sessionEncryptKey)
	if err != nil {
		return fmt.Errorf("newCipher: %w", err)
	}
	decryptedText := make([]byte, len(cipherText[aes.BlockSize:]))
	decryptStream := cipher.NewCTR(block, cipherText[:aes.BlockSize])
	decryptStream.XORKeyStream(decryptedText, cipherText[aes.BlockSize:])

	if err := json.Unmarshal(decryptedText, s); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	return nil
}

func (s *googleODICSession) MarshalCookie(w http.ResponseWriter, sessionEncryptKey []byte) error {
	plainText, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	block, err := aes.NewCipher(sessionEncryptKey)
	if err != nil {
		return fmt.Errorf("newCipher: %w", err)
	}
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return fmt.Errorf("readFull: %w", err)
	}
	encryptStream := cipher.NewCTR(block, iv)
	encryptStream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	sessionStr := base64.RawStdEncoding.EncodeToString(cipherText)
	cookie := &http.Cookie{
		Name:     "ls3viewer-session",
		Value:    sessionStr,
		MaxAge:   int((24 * time.Hour).Seconds()),
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
	return nil
}

type googleOIDCHandler struct {
	clientID          string
	clientSecret      string
	sessionEncryptKey []byte
	next              http.Handler
	opts              *Options
}

func (h *googleOIDCHandler) newOIDCConfig(ctx context.Context, baseURL *url.URL) (*oidc.Provider, *oauth2.Config, error) {
	u := *baseURL
	u.Path = filepath.Join(u.Path, "/oidc/idpresponse")
	provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		return nil, nil, err
	}
	cfg := &oauth2.Config{
		ClientID:     h.clientID,
		ClientSecret: h.clientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID},
		RedirectURL:  u.String(),
	}
	return provider, cfg, nil
}

func (h *googleOIDCHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.opts.Logger("debug", "enter oidc middleware")
	baseURL, err := h.opts.getBaseURL(r)
	if err != nil {
		h.opts.Logger("error", err)
		http.Error(w, fmt.Sprintf("%s", err), http.StatusInternalServerError)
		return
	}
	h.opts.Logger("debug", "base url", baseURL.String())

	var session googleODICSession
	if err := session.UnmarshalCookie(r, h.sessionEncryptKey); err != nil {
		h.opts.Logger("debug", "session restore", err)
	}
	if path.Join(baseURL.Path, "/oidc/login") == r.URL.Path {
		h.handleLogin(w, r, &session, baseURL)
		return
	}
	if path.Join(baseURL.Path, "/oidc/idpresponse") == r.URL.Path {
		h.handleCallback(w, r, &session, baseURL)
	}
	h.handleDefault(w, r, &session, baseURL)
}

func (h *googleOIDCHandler) handleLogin(w http.ResponseWriter, r *http.Request, session *googleODICSession, baseURL *url.URL) {
	_, cfg, err := h.newOIDCConfig(r.Context(), baseURL)
	if err != nil {
		h.opts.Logger("error", err)
		http.Error(w, fmt.Sprintf("%s", err), http.StatusInternalServerError)
		return
	}
	session.RedirectTo = baseURL.String()
	if returnPath := r.URL.Query().Get("return"); returnPath != "" {
		redirectTo := *baseURL
		redirectTo.Path = returnPath
		session.RedirectTo = redirectTo.String()
	}

	state := randstr.Hex(16)
	session.S = state
	if err := session.MarshalCookie(w, h.sessionEncryptKey); err != nil {
		h.opts.Logger("error", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	authURL := cfg.AuthCodeURL(state)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (h *googleOIDCHandler) handleCallback(w http.ResponseWriter, r *http.Request, session *googleODICSession, baseURL *url.URL) {
	ctx := r.Context()
	provider, cfg, err := h.newOIDCConfig(ctx, baseURL)
	if err != nil {
		h.opts.Logger("error", err)
		http.Error(w, fmt.Sprintf("%s", err), http.StatusInternalServerError)
		return
	}
	state := r.URL.Query().Get("state")
	if session.S == "" {
		h.opts.Logger("error", "cookie s empty")
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	expectedState := session.S
	session.S = ""
	redirectTo := baseURL.String()
	if session.RedirectTo != "" {
		redirectTo = session.RedirectTo
		session.RedirectTo = ""
	}
	h.opts.Logger("debug", "redirectTo", redirectTo)
	if state != expectedState {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	code := r.URL.Query().Get("code")
	oauth2Token, err := cfg.Exchange(ctx, code)
	if err != nil {
		err = fmt.Errorf("failed to exchange token: %w", err)
		h.opts.Logger("error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		h.opts.Logger("error", "missing token")
		http.Error(w, "missing token", http.StatusInternalServerError)
		return
	}
	session.IDToken = rawIDToken
	idTokenClaims, exp, err := h.checkIDToken(ctx, provider, rawIDToken)
	if err != nil {
		h.opts.Logger("error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if exp.IsZero() {
		exp = time.Now().Add(time.Hour)
	}
	if err := session.MarshalCookie(w, h.sessionEncryptKey); err != nil {
		h.opts.Logger("error", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	h.opts.Logger("info", "login:", idTokenClaims["sub"], " exp:", exp)
	http.Redirect(w, r, redirectTo, http.StatusFound)
}

func (h *googleOIDCHandler) handleDefault(w http.ResponseWriter, r *http.Request, session *googleODICSession, baseURL *url.URL) {
	ctx := r.Context()
	provider, _, err := h.newOIDCConfig(ctx, baseURL)
	if err != nil {
		h.opts.Logger("error", err)
		http.Error(w, fmt.Sprintf("%s", err), http.StatusInternalServerError)
		return
	}
	loginURL := *baseURL
	loginURL.Path = path.Join(loginURL.Path, "/oidc/login")
	query := &url.Values{
		"return": []string{r.URL.Path},
	}
	loginURL.RawQuery = query.Encode()
	h.opts.Logger("debug", "login url =", loginURL.String())
	if session.IDToken == "" {
		http.Redirect(w, r, loginURL.String(), http.StatusFound)
		return
	}
	_, exp, err := h.checkIDToken(r.Context(), provider, session.IDToken)
	if err != nil {
		http.Redirect(w, r, loginURL.String(), http.StatusFound)
		return
	}
	if time.Until(exp) < 0 {
		h.opts.Logger("debug", "expired", exp, "until", time.Until(exp))
		http.Redirect(w, r, loginURL.String(), http.StatusFound)
		return
	}
	h.next.ServeHTTP(w, r)
}

func (h *googleOIDCHandler) checkIDToken(ctx context.Context, provider *oidc.Provider, rawIDToken string) (map[string]interface{}, time.Time, error) {
	oidcConfig := &oidc.Config{
		ClientID: h.clientID,
	}
	verifier := provider.Verifier(oidcConfig)
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to verify ID Token: : %w", err)
	}
	idTokenClaims := map[string]interface{}{}
	if err := idToken.Claims(&idTokenClaims); err != nil {
		return nil, time.Time{}, err
	}
	var exp time.Time
	if v, ok := idTokenClaims["exp"].(float64); ok {
		exp = time.Unix(int64(v), 0)
	}
	return idTokenClaims, exp, nil
}

func WithAccessLogger() func(*Options) {
	return func(o *Options) {
		o.Middleware = append(o.Middleware, func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				o.Logger("info", r.Method, r.URL.Path, r.Host)
				next.ServeHTTP(w, r)
			})
		})
	}
}

func WithRecover() func(*Options) {
	return func(o *Options) {
		o.Middleware = append(o.Middleware, func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer func() {
					if err := recover(); err != nil {
						o.Logger("error", fmt.Sprintf("%#v", err))
						for depth := 0; ; depth++ {
							_, file, line, ok := runtime.Caller(depth)
							if !ok {
								break
							}
							o.Logger("info", fmt.Sprintf("======> %d: %v:%d", depth, file, line))
						}
					}
				}()
				next.ServeHTTP(w, r)
			})
		})
	}
}

func WithLogger(l LoggerFunc) func(*Options) {
	return func(o *Options) {
		if l != nil {
			o.Logger = l
		}
	}
}
