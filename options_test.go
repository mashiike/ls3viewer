package ls3viewer

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGoogleODICSession(t *testing.T) {
	key := []byte("passpasspasspass")
	session := &googleODICSession{
		IDToken:    "hogehoge",
		RedirectTo: "http://localhost:8080",
		S:          "hoge",
	}
	w := httptest.NewRecorder()
	err := session.MarshalCookie(w, key)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, cookie := range w.Result().Cookies() {
		r.AddCookie(cookie)
	}
	var restore googleODICSession
	err = restore.UnmarshalCookie(r, key)
	require.NoError(t, err)
	require.EqualValues(t, *session, restore)
}

func TestWildcardMatch(t *testing.T) {
	cases := []struct {
		str      string
		pattern  string
		expected bool
	}{
		{str: "hoge@example.com", pattern: "hoge@example.com", expected: true},
		{str: "fuga@example.com", pattern: "hoge@example.com", expected: false},
		{str: "Hoge@example.com", pattern: "hoge@example.com", expected: true},
		{str: "hoge@example.com", pattern: "@example.com", expected: true},
		{str: "hoge@dummy.example.com", pattern: "@example.com", expected: false},
		{str: "hoge@dummy.example.com", pattern: "@*example.com", expected: true},
		{str: "fuga@dummy.example.com", pattern: "hoge@*example.com", expected: false},
		{str: "fuga@dummy.example.com", pattern: "*g*@*example.com", expected: true},
		{str: "fuga@dummy.example.com", pattern: "h*g*@*example.com", expected: false},
		{str: "hoge@dummy.example.com", pattern: "h*g*@*example.com", expected: true},
		{str: "hoga@dummy.example.com", pattern: "h*g*@*example.com", expected: true},
	}
	for _, c := range cases {
		t.Run(fmt.Sprint(c.pattern, c.str), func(t *testing.T) {
			actual := wildcardMatch(c.pattern, c.str)
			require.Equal(t, c.expected, actual)
		})
	}
}
