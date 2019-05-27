package services

import (
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	h "github.com/BNPrashanth/oauth2/helpers"

	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/linkedin"
)

var (
	oauthConfLn = &oauth2.Config{
		ClientID:     "",
		ClientSecret: "",
		RedirectURL:  "http://localhost:9090/callback-ln",
		Scopes:       []string{"r_liteprofile", "r_emailaddress"},
		Endpoint:     linkedin.Endpoint,
	}
	oauthStateStringLn = ""
)

/*
InitializeOAuthLinkedin Function
*/
func InitializeOAuthLinkedin() {
	oauthConfLn.ClientID = viper.GetString("linkedin.clientID")
	oauthConfLn.ClientSecret = viper.GetString("linkedin.clentSecret")
	oauthStateStringLn = viper.GetString("oauthStateString")
}

/*
HandleLinkedinLogin Function
*/
func HandleLinkedinLogin(w http.ResponseWriter, r *http.Request) {
	URL, err := url.Parse(oauthConfLn.Endpoint.AuthURL)
	if err != nil {
		log.Fatal("Parse: ", err)
	}
	h.Log.Info(URL.String())
	parameters := url.Values{}
	parameters.Add("client_id", oauthConfLn.ClientID)
	parameters.Add("scope", strings.Join(oauthConfLn.Scopes, " "))
	parameters.Add("redirect_uri", oauthConfLn.RedirectURL)
	parameters.Add("response_type", "code")
	parameters.Add("state", oauthStateStringLn)
	URL.RawQuery = parameters.Encode()
	url := URL.String()
	h.Log.Info(url)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

/*
CallBackFromLinkedin Function
*/
func CallBackFromLinkedin(w http.ResponseWriter, r *http.Request) {
	h.Log.Info("Callback-ln..")

	state := r.FormValue("state")
	h.Log.Info(state)
	if state != oauthStateStringLn {
		h.Log.Info("invalid oauth state, expected " + oauthStateStringLn + ", got " + state + "\n")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	code := r.FormValue("code")
	h.Log.Info(code)

	if code == "" {
		h.Log.Warn("Code not found..")
		w.Write([]byte("Code Not Found to provide AccessToken..\n"))
		reason := r.FormValue("error")
		if reason == "user_cancelled_login" {
			description := r.FormValue("error_description")
			w.Write([]byte(description))
		}
		// User has denied access..
		// http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	} else {
		token, err := oauthConfLn.Exchange(oauth2.NoContext, code)
		if err != nil {
			h.Log.Error("oauthConfLn.Exchange() failed with " + err.Error() + "\n")
			return
		}
		h.Log.Info("TOKEN>> AccessToken>> " + token.AccessToken)
		h.Log.Info("TOKEN>> Expiration Time>> " + token.Expiry.String())
		h.Log.Info("TOKEN>> RefreshToken>> " + token.RefreshToken)

		client := oauthConfLn.Client(oauth2.NoContext, token)
		req, err := http.NewRequest("GET", "https://api.linkedin.com/v2/me", nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req.Header.Set("Bearer", token.AccessToken)
		resp, err := client.Do(req)
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
