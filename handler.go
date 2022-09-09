package ls3viewer

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/dustin/go-humanize"
	"github.com/mattn/go-encoding"
	"github.com/saintfish/chardet"
	"golang.org/x/net/html/charset"
)

func MustNew(bucketName string, objectKeyPrefix string, optFns ...func(*Options)) http.Handler {
	h, err := New(bucketName, objectKeyPrefix, optFns...)
	if err != nil {
		panic(err)
	}
	return h
}

type handler struct {
	bucketName      string
	objectKeyPrefix string
	tmpl            *template.Template
	opts            *Options
	downloader      *manager.Downloader
}

func New(bucketName string, objectKeyPrefix string, optFns ...func(*Options)) (http.Handler, error) {
	if bucketName == "" {
		return nil, errors.New("bucket name is required")
	}
	opts := newOptions()
	for _, optFn := range optFns {
		optFn(opts)
	}
	if err := opts.buildOptions(); err != nil {
		return nil, err
	}

	tmpl, err := newTemplate(opts)
	if err != nil {
		return nil, err
	}
	var h http.Handler
	h = &handler{
		bucketName:      bucketName,
		objectKeyPrefix: objectKeyPrefix,
		tmpl:            tmpl,
		opts:            opts,
		downloader:      manager.NewDownloader(opts.S3Client),
	}
	for _, middleware := range opts.Middleware {
		h = middleware(h)
	}
	return h, nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/favicon.ico" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	h.opts.Logger("debug", "enter handler")
	data, err := h.buildTemplateData(r)
	if err != nil {
		h.opts.Logger("error", err)
		http.Error(w, fmt.Sprintf("%s", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.tmpl.ExecuteTemplate(w, templateName, data)
}

func (h *handler) buildTemplateData(r *http.Request) (map[string]interface{}, error) {
	ctx := r.Context()
	baseURL, err := h.opts.getBaseURL(ctx)
	if err != nil {
		return nil, err
	}
	baseURL.Path = ""

	prefix := strings.TrimPrefix(r.URL.Path, "/")
	keyPrefix := h.objectKeyPrefix + prefix
	h.opts.Logger("debug", "url path  => s3 key prefix: ", r.URL.Path, " => ", keyPrefix)
	resp, err := h.listObjects(ctx, keyPrefix)
	if err != nil {
		return nil, err
	}
	data := map[string]interface{}{
		"Prefix":  prefix,
		"res":     resp,
		"BaseURL": baseURL.String(),
	}

	if content, ok := h.matchSingleObject(resp.Contents, keyPrefix); ok {
		resp.KeyCount = 1
		resp.Contents = []types.Object{*content}
		contentBody, viewable, err := h.getObject(ctx, *content)
		if err != nil {
			return nil, err
		}
		if viewable {
			data["ContentBody"] = contentBody
		}
	}
	for i := range resp.Contents {
		*resp.Contents[i].Key = strings.TrimPrefix(*resp.Contents[i].Key, h.objectKeyPrefix)
	}
	return data, nil
}

func (h *handler) listObjects(ctx context.Context, keyPrefix string) (*s3.ListObjectsV2Output, error) {
	params := &s3.ListObjectsV2Input{
		Bucket:    aws.String(h.bucketName),
		Delimiter: aws.String("/"),
		Prefix:    aws.String(keyPrefix),
		MaxKeys:   1000,
	}
	p := s3.NewListObjectsV2Paginator(h.opts.S3Client, params)
	var resp *s3.ListObjectsV2Output
	for p.HasMorePages() {
		output, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		if resp == nil {
			resp = output
		} else {
			resp.KeyCount += output.KeyCount
			resp.Contents = append(resp.Contents, output.Contents...)
		}
	}
	return resp, nil
}

func (h *handler) matchSingleObject(contents []types.Object, keyPrefix string) (*types.Object, bool) {
	if len(contents) > 100 {
		return nil, false
	}
	for _, content := range contents {
		if strings.EqualFold(*content.Key, keyPrefix) {
			return &content, true
		}
	}
	return nil, false
}

func (h *handler) getObject(ctx context.Context, obj types.Object) (string, bool, error) {
	output, err := h.opts.S3Client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(h.bucketName),
		Key:    obj.Key,
	})
	if err != nil {
		return "", false, err
	}
	h.opts.Logger("debug", *obj.Key, *output.ContentType)

	h.opts.Logger("debug", "try get content body")
	buf := make([]byte, 512)
	writeAtBuffer := manager.NewWriteAtBuffer(buf)
	_, err = h.downloader.Download(ctx, writeAtBuffer, &s3.GetObjectInput{
		Bucket: aws.String(h.bucketName),
		Key:    obj.Key,
	}, func(d *manager.Downloader) {
		d.BufferProvider = manager.NewPooledBufferedWriterReadFromProvider(5 * 1024 * 1024) //5MB
	})
	if err != nil {
		return "", false, err
	}
	body := writeAtBuffer.Bytes()[:output.ContentLength]

	filename := path.Base(*obj.Key)
	if strings.HasSuffix(filename, ".gz") {
		h.opts.Logger("debug", "try decompress")
		gr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			h.opts.Logger("debug", "err decompress", err)
			return "", false, err
		}
		defer gr.Close()
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, gr); err != nil {
			h.opts.Logger("debug", "copy", err)
			return "", false, err
		}
		decompressedBody := buf.Bytes()
		if !utf8.Valid(decompressedBody) {
			return "", false, err
		}
		return string(decompressedBody), true, nil
	}
	switch path.Ext(filename) {
	case ".log", ".json", ".yaml", ".yml", ".sql", ".txt":
	default:
		contentType := strings.ToLower(*output.ContentType)
		if !strings.HasPrefix(contentType, "text/") &&
			!strings.HasPrefix(contentType, "application/json") &&
			!strings.HasPrefix(contentType, "binary/octet-stream") {
			return "", false, nil
		}
	}

	h.opts.Logger("debug", "may be text, try detect encoding")
	reader := io.Reader(bytes.NewReader(body))
	r, ok := convertTextEncoding(h.opts, reader, *output.ContentType)
	if !ok {
		return "", false, nil
	}
	convertedBody, err := io.ReadAll(r)
	if err != nil {
		h.opts.Logger("warn", *obj.Key, *output.ContentType, "convert text encoding", err)
		return "", false, nil
	}
	if utf8.Valid(convertedBody) {
		return string(convertedBody), true, nil
	}
	h.opts.Logger("debug", "converted body is urf8 invalid, check original body")
	if utf8.Valid(body) {
		return string(body), true, nil
	}
	h.opts.Logger("debug", "original body utf invalid, maybe not text")
	return "", false, nil
}

const templateName = "index.html"

func newTemplate(opts *Options) (*template.Template, error) {
	tmpl := template.New(templateName)
	tmpl.Funcs(template.FuncMap{
		"isDir": func(s *string) bool {
			return strings.HasSuffix(*s, "/")
		},
		"bytes": func(s *int64) string {
			return humanize.Bytes(uint64(*s))
		},
		"basename": func(s *string) string {
			return path.Base(*s)
		},
	})
	if _, err := tmpl.Parse(opts.HTMLTemplate); err != nil {
		return nil, fmt.Errorf("html template parse: %w", err)
	}
	return tmpl, nil
}

func convertTextEncoding(opts *Options, reader io.Reader, conentType string) (io.Reader, bool) {
	br := bufio.NewReader(reader)
	var r io.Reader = br
	if data, err := br.Peek(2048); err == nil || err == io.EOF {
		enc, name, ok := charset.DetermineEncoding(data, conentType)
		opts.Logger("debug", name, ok)
		if !ok {
			det := chardet.NewTextDetector()
			res, err := det.DetectAll(data)
			if err != nil {
				return nil, false
			}
			maxConfidence := 0
			for _, c := range res {
				opts.Logger("debug", c.Language, c.Confidence, c.Charset)
				if c.Confidence >= maxConfidence {
					maxConfidence = c.Confidence
					name = c.Charset
				}
				if maxConfidence <= 25 {
					return nil, false
				}
			}
			opts.Logger("debug", name, maxConfidence)
		}
		if enc != nil {
			r = enc.NewDecoder().Reader(br)
		} else if name != "" {
			if enc := encoding.GetEncoding(name); enc != nil {
				r = enc.NewDecoder().Reader(br)
			}
		}
	} else {
		opts.Logger("debug", "peek error", err)
	}
	return r, true
}
