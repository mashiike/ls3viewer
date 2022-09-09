package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/fatih/color"
	"github.com/fujiwara/logutils"
	"github.com/fujiwara/ridge"
	"github.com/handlename/ssmwrap"
	"github.com/ken39arg/go-flagx"
	"github.com/mashiike/ls3viewer"
)

func main() {
	filter := &logutils.LevelFilter{
		Levels: []logutils.LogLevel{"debug", "info", "notice", "warn", "error"},
		ModifierFuncs: []logutils.ModifierFunc{
			logutils.Color(color.FgHiBlack),
			nil,
			logutils.Color(color.FgHiBlue),
			logutils.Color(color.FgYellow),
			logutils.Color(color.FgRed, color.BgBlack),
		},
		MinLevel: "info",
		Writer:   os.Stderr,
	}
	log.SetOutput(filter)
	ssmwrapPaths := os.Getenv("SSMWRAP_PATHS")
	paths := strings.Split(ssmwrapPaths, ",")
	if ssmwrapPaths != "" && len(paths) > 0 {
		err := ssmwrap.Export(ssmwrap.ExportOptions{
			Paths:   paths,
			Retries: 3,
		})
		if err != nil {
			log.Fatalf("[error] %v", err)
		}
	}
	ssmwrapNames := os.Getenv("SSMWRAP_NAMES")
	names := strings.Split(ssmwrapNames, ",")
	if ssmwrapNames != "" && len(names) > 0 {
		err := ssmwrap.Export(ssmwrap.ExportOptions{
			Names:   names,
			Retries: 3,
		})
		if err != nil {
			log.Fatalf("[error] %v", err)
		}
	}
	var (
		bucketName      string
		objectKeyPrefix string
		address         string
		logLevel        string

		basicUser          string
		basicPass          string
		googleClientID     string
		googleClientSecret string
		encryptKey         string
	)
	flag.StringVar(&bucketName, "bucket-name", "", "s3 bucket name")
	flag.StringVar(&objectKeyPrefix, "key-prefix", "", "object-key-prefix")
	flag.StringVar(&address, "address", ":8080", "local server address")
	flag.StringVar(&basicUser, "basic-user", "", "basic auth user")
	flag.StringVar(&basicPass, "basic-pass", "", "basic auth pass")
	flag.StringVar(&googleClientID, "google-client-id", "", "google oidc client id")
	flag.StringVar(&googleClientSecret, "google-client-secret", "", "google oidc client secret")
	flag.StringVar(&encryptKey, "session-encrypt-key", "6vHtOhaRvpCT5M8caYniHUZEKEd4aaev", "oidc session encrypt key")
	flag.StringVar(&logLevel, "log-level", "info", "log-level")
	flag.VisitAll(flagx.EnvToFlag)
	flag.VisitAll(flagx.EnvToFlagWithPrefix("LS3VIEWER_"))
	flag.Parse()
	filter.SetMinLevel(logutils.LogLevel(logLevel))

	optFns := make([]func(*ls3viewer.Options), 0)
	if basicUser != "" && basicPass != "" {
		log.Println("[info] enable basic auth")
		optFns = append(optFns, ls3viewer.WithBasicAuth(basicUser, basicPass))
	}
	if googleClientID != "" && googleClientSecret != "" {
		log.Println("[info] google oidc auth")
		key := []byte(encryptKey)
		keyLen := len(key)
		if keyLen != 16 && keyLen != 24 && keyLen != 32 {
			log.Fatalln("session encrypt key length must 16, 24 or 32 byte")
		}
		optFns = append(optFns, ls3viewer.WithGoogleOIDC(googleClientID, googleClientSecret, key))
	}
	optFns = append(optFns, ls3viewer.WithAccessLogger())
	optFns = append(optFns, ls3viewer.WithRecover())
	h, err := ls3viewer.New(bucketName, objectKeyPrefix, optFns...)
	if err != nil {
		log.Fatalln(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/", h)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer cancel()
	ridge.RunWithContext(ctx, address, "/", mux)
}
