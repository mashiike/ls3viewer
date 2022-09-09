package ls3viewer

import (
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
