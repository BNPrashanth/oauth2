package services

import (
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	h "github.com/BNPrashanth/oauth2/helpers"

	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var (
	oauthConfGl = &oauth2.Config{
		ClientID:     "",
		ClientSecret: "",
		RedirectURL:  "http://localhost:9090/callback-gl",
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}
	oauthStateStringGl = ""
)

/*
InitializeOAuthGoogle Function
*/
func InitializeOAuthGoogle() {
	oauthConfGl.ClientID = viper.GetString("google.clientID")
	oauthConfGl.ClientSecret = viper.GetString("google.clientSecret")
	oauthStateStringGl = viper.GetString("oauthStateString")
}

/*
HandleGoogleLogin Function
*/
func HandleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	URL, err := url.Parse(oauthConfGl.Endpoint.AuthURL)
	if err != nil {
		h.Log.Error("Parse: " + err.Error())
	}
	h.Log.Info(URL.String())
	parameters := url.Values{}
	parameters.Add("client_id", oauthConfGl.ClientID)
	parameters.Add("scope", strings.Join(oauthConfGl.Scopes, " "))
	parameters.Add("redirect_uri", oauthConfGl.RedirectURL)
	parameters.Add("response_type", "code")
	parameters.Add("state", oauthStateStringGl)
	URL.RawQuery = parameters.Encode()
	url := URL.String()
	h.Log.Info(url)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

/*
CallBackFromGoogle Function
*/
func CallBackFromGoogle(w http.ResponseWriter, r *http.Request) {
	h.Log.Info("Callback-gl..")

	state := r.FormValue("state")
	h.Log.Info(state)
	if state != oauthStateStringGl {
		h.Log.Info("invalid oauth state, expected " + oauthStateStringGl + ", got " + state + "\n")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	code := r.FormValue("code")
	h.Log.Info(code)

	if code == "" {
		h.Log.Warn("Code not found..")
		w.Write([]byte("Code Not Found to provide AccessToken..\n"))
		reason := r.FormValue("error_reason")
		if reason == "user_denied" {
			w.Write([]byte("User has denied Permission.."))
		}
		// User has denied access..
		// http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	} else {
		token, err := oauthConfGl.Exchange(oauth2.NoContext, code)
		if err != nil {
			h.Log.Error("oauthConfGl.Exchange() failed with " + err.Error() + "\n")
			return
		}
		h.Log.Info("TOKEN>> AccessToken>> " + token.AccessToken)
		h.Log.Info("TOKEN>> Expiration Time>> " + token.Expiry.String())
		h.Log.Info("TOKEN>> RefreshToken>> " + token.RefreshToken)

		resp, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + url.QueryEscape(token.AccessToken))
		if err != nil {
			h.Log.Error("Get: " + err.Error() + "\n")
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}
		defer resp.Body.Close()

		response, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			h.Log.Error("ReadAll: " + err.Error() + "\n")
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		h.Log.Info("parseResponseBody: " + string(response) + "\n")

		w.Write([]byte("Hello, I'm protected\n"))
		w.Write([]byte(string(response)))
		return
	}
}
