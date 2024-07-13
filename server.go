package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/evan-buss/opds-proxy/convert"
	"github.com/evan-buss/opds-proxy/html"
	"github.com/evan-buss/opds-proxy/opds"
	"github.com/gorilla/securecookie"
)

const (
	MOBI_MIME = "application/x-mobipocket-ebook"
	EPUB_MIME = "application/epub+zip"
	ATOM_MIME = "application/atom+xml"
)

var (
	_ = mime.AddExtensionType(".epub", EPUB_MIME)
	_ = mime.AddExtensionType(".kepub.epub", EPUB_MIME)
	_ = mime.AddExtensionType(".mobi", MOBI_MIME)
)

type Server struct {
	addr   string
	router *http.ServeMux
	s      *securecookie.SecureCookie
}

type Credentials struct {
	Username string
	Password string
}

func NewServer(config *config) (*Server, error) {
	hashKey, err := hex.DecodeString(config.Auth.HashKey)
	if err != nil {
		return nil, err
	}
	blockKey, err := hex.DecodeString(config.Auth.BlockKey)
	if err != nil {
		return nil, err
	}

	s := securecookie.New(hashKey, blockKey)

	router := http.NewServeMux()
	router.HandleFunc("GET /{$}", handleHome(config.Feeds))
	router.HandleFunc("GET /feed", handleFeed("tmp/", s))
	router.HandleFunc("/auth", handleAuth(s))
	router.Handle("GET /static/", http.FileServer(http.FS(html.StaticFiles())))

	return &Server{
		addr:   ":" + config.Port,
		router: router,
		s:      s,
	}, nil
}

func (s *Server) Serve() {
	slog.Info("Starting server", slog.String("port", s.addr))
	log.Fatal(http.ListenAndServe(s.addr, s.router))
}

func handleHome(feeds []feedConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vmFeeds := make([]html.FeedInfo, len(feeds))
		for i, feed := range feeds {
			vmFeeds[i] = html.FeedInfo{
				Title: feed.Name,
				URL:   feed.Url,
			}
		}

		html.Home(w, vmFeeds, partial(r))
	}
}

func handleFeed(outputDir string, s *securecookie.SecureCookie) http.HandlerFunc {
	kepubConverter := &convert.KepubConverter{}
	mobiConverter := &convert.MobiConverter{}

	return func(w http.ResponseWriter, r *http.Request) {
		queryURL := r.URL.Query().Get("q")
		if queryURL == "" {
			http.Error(w, "No feed specified", http.StatusBadRequest)
			return
		}

		parsedUrl, err := url.PathUnescape(queryURL)
		queryURL = parsedUrl
		if err != nil {
			handleError(r, w, "Failed to parse URL", err)
			return
		}

		searchTerm := r.URL.Query().Get("search")
		if searchTerm != "" {
			queryURL = replaceSearchPlaceHolder(queryURL, searchTerm)
		}

		resp, err := fetchFromUrl(queryURL, getCredentials(r, s))
		if err != nil {
			handleError(r, w, "Failed to fetch", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized {
			http.Redirect(w, r, "/auth?return="+r.URL.String(), http.StatusFound)
			return
		}

		contentType := resp.Header.Get("Content-Type")
		mimeType, _, err := mime.ParseMediaType(contentType)
		if err != nil {
			handleError(r, w, "Failed to parse content type", err)
		}

		if mimeType == ATOM_MIME {
			feed, err := opds.ParseFeed(resp.Body)
			if err != nil {
				handleError(r, w, "Failed to parse feed", err)
				return
			}

			feedParams := html.FeedParams{
				URL:  queryURL,
				Feed: feed,
			}

			if err = html.Feed(w, feedParams, partial(r)); err != nil {
				handleError(r, w, "Failed to render feed", err)
				return
			}
		}

		var converter convert.Converter
		if strings.Contains(r.UserAgent(), "Kobo") && kepubConverter.Available() {
			converter = kepubConverter
		} else if strings.Contains(r.UserAgent(), "Kindle") && mobiConverter.Available() {
			converter = mobiConverter
		}

		if mimeType != EPUB_MIME || converter == nil {
			forwardResponse(w, resp)
			return
		}

		filename, err := parseFileName(resp)
		if err != nil {
			handleError(r, w, "Failed to parse file name", err)
		}

		epubFile := filepath.Join(outputDir, filename)
		downloadFile(epubFile, resp)
		defer os.Remove(epubFile)

		outputFile, err := converter.Convert(epubFile)
		if err != nil {
			handleError(r, w, "Failed to convert epub", err)
		}

		if err = sendConvertedFile(w, outputFile); err != nil {
			handleError(r, w, "Failed to send converted file", err)
		}
	}
}

func handleAuth(s *securecookie.SecureCookie) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		returnUrl := r.URL.Query().Get("return")
		if returnUrl == "" {
			http.Error(w, "No return URL specified", http.StatusBadRequest)
			return
		}

		if r.Method == "GET" {
			html.Login(w, html.LoginParams{ReturnURL: returnUrl}, partial(r))
			return
		}

		if r.Method == "POST" {
			username := r.FormValue("username")
			password := r.FormValue("password")

			rUrl, err := url.Parse(returnUrl)
			if err != nil {
				http.Error(w, "Invalid return URL", http.StatusBadRequest)
			}
			domain, err := url.Parse(rUrl.Query().Get("q"))
			if err != nil {
				http.Error(w, "Invalid site", http.StatusBadRequest)
			}

			value := map[string]Credentials{
				domain.Hostname(): {Username: username, Password: password},
			}

			encoded, err := s.Encode("auth-creds", value)
			if err != nil {
				handleError(r, w, "Failed to encode credentials", err)
				return
			}
			cookie := &http.Cookie{
				Name:  "auth-creds",
				Value: encoded,
				Path:  "/",
				// Kobo fails to set cookies with HttpOnly or Secure flags
				Secure:   false,
				HttpOnly: false,
			}

			http.SetCookie(w, cookie)
			http.Redirect(w, r, returnUrl, http.StatusFound)
			return
		}

		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func getCredentials(r *http.Request, s *securecookie.SecureCookie) *Credentials {
	cookie, err := r.Cookie("auth-creds")
	if err != nil {
		return nil
	}

	value := make(map[string]*Credentials)
	if err = s.Decode("auth-creds", cookie.Value, &value); err != nil {
		return nil
	}

	if !r.URL.Query().Has("q") {
		return nil
	}

	feedUrl, err := url.Parse(r.URL.Query().Get("q"))
	if err != nil {
		return nil
	}

	return value[feedUrl.Hostname()]
}

func fetchFromUrl(url string, credentials *Credentials) (*http.Response, error) {
	client := &http.Client{
		Timeout: 2 * time.Second,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if credentials != nil {
		req.SetBasicAuth(credentials.Username, credentials.Password)
	}

	return client.Do(req)
}

func handleError(r *http.Request, w http.ResponseWriter, message string, err error) {
	slog.Error(message, slog.String("path", r.URL.RawPath), slog.Any("error", err))
	http.Error(w, "An unexpected error occurred", http.StatusInternalServerError)
}

func replaceSearchPlaceHolder(url string, searchTerm string) string {
	return strings.Replace(url, "{searchTerms}", searchTerm, 1)
}

func partial(req *http.Request) string {
	return req.URL.Query().Get("partial")
}

func downloadFile(path string, resp *http.Response) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return err
	}

	return nil
}

func parseFileName(resp *http.Response) (string, error) {
	contentDisposition := resp.Header.Get("Content-Disposition")
	_, params, err := mime.ParseMediaType(contentDisposition)
	if err != nil {
		return "", err
	}

	return params["filename"], nil
}

func forwardResponse(w http.ResponseWriter, resp *http.Response) {
	for k, v := range resp.Header {
		w.Header()[k] = v
	}

	io.Copy(w, resp.Body)
}

func sendConvertedFile(w http.ResponseWriter, filePath string) error {
	defer os.Remove(filePath)
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}

	info, err := file.Stat()
	if err != nil {
		return err
	}

	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	w.Header().Set("Content-Disposition",
		mime.FormatMediaType(
			"attachment",
			map[string]string{"filename": filepath.Base(filePath)},
		),
	)
	w.Header().Set("Content-Type", mime.TypeByExtension(filepath.Ext(filePath)))

	_, err = io.Copy(w, file)
	if err != nil {
		return err
	}

	return nil
}
