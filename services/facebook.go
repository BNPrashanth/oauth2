package services

import (
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	h "github.com/BNPrashanth/oauth2/helpers"

	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
)

var (
	oauthConfFb = &oauth2.Config{
		ClientID:     "",
		ClientSecret: "",
		RedirectURL:  "http://localhost:9090/callback-fb",
		Scopes:       []string{"public_profile"},
		Endpoint:     facebook.Endpoint,
	}
	oauthStateStringFb = ""
)

/*
InitializeOAuthFacebook Function
*/
func InitializeOAuthFacebook() {
	oauthConfFb.ClientID = viper.GetString("facebook.clientID")
	oauthConfFb.ClientSecret = viper.GetString("facebook.clentSecret")
	oauthStateStringFb = viper.GetString("oauthStateString")
}

/*
HandleFacebookLogin Function
*/
func HandleFacebookLogin(w http.ResponseWriter, r *http.Request) {
	URL, err := url.Parse(oauthConfFb.Endpoint.AuthURL)
	if err != nil {
		h.Log.Error("Parse: " + err.Error())
	}
	h.Log.Info(URL.String())
	parameters := url.Values{}
	parameters.Add("client_id", oauthConfFb.ClientID)
	parameters.Add("scope", strings.Join(oauthConfFb.Scopes, " "))
	parameters.Add("redirect_uri", oauthConfFb.RedirectURL)
	parameters.Add("response_type", "code")
	parameters.Add("state", oauthStateStringFb)
	URL.RawQuery = parameters.Encode()
	url := URL.String()
	h.Log.Info(url)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

/*
CallBackFromFacebook Function
*/
func CallBackFromFacebook(w http.ResponseWriter, r *http.Request) {
	h.Log.Info("Callback-fb..")

	state := r.FormValue("state")
	h.Log.Info(state)
	if state != oauthStateStringFb {
		h.Log.Info("invalid oauth state, expected " + oauthStateStringFb + ", got " + state + "\n")
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
		token, err := oauthConfFb.Exchange(oauth2.NoContext, code)
		if err != nil {
			h.Log.Error("oauthConfFb.Exchange() failed with " + err.Error() + "\n")
			return
		}
		h.Log.Info("TOKEN>> AccessToken>> " + token.AccessToken)
		h.Log.Info("TOKEN>> Expiration Time>> " + token.Expiry.String())
		h.Log.Info("TOKEN>> RefreshToken>> " + token.RefreshToken)

		h.Log.Info("https://graph.facebook.com/me?access_token=" + url.QueryEscape(token.AccessToken) + "&fields=email")
		resp, err := http.Get("https://graph.facebook.com/me?access_token=" +
			url.QueryEscape(token.AccessToken) + "&fields=email")
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
