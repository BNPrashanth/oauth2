package main

import (
	"log"
	"net/http"

	h "github.com/BNPrashanth/oauth2/helpers"
	s "github.com/BNPrashanth/oauth2/services"
	"github.com/spf13/viper"
)

func main() {
	h.InitializeViper()
	h.InitializeZapCustomLogger()

	s.InitializeOAuthFacebook()
	s.InitializeOAuthLinkedin()
	s.InitializeOAuthGoogle()

	http.HandleFunc("/", handleMain)
	http.HandleFunc("/login-fb", s.HandleFacebookLogin)
	http.HandleFunc("/callback-fb", s.CallBackFromFacebook)
	http.HandleFunc("/login-ln", s.HandleLinkedinLogin)
	http.HandleFunc("/callback-ln", s.CallBackFromLinkedin)
	http.HandleFunc("/login-gl", s.HandleGoogleLogin)
	http.HandleFunc("/callback-gl", s.CallBackFromGoogle)
	h.Log.Info("Started running on http://localhost:" + viper.GetString("port"))
	log.Fatal(http.ListenAndServe(":"+viper.GetString("port"), nil))

}

func handleMain(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(h.IndexPage))
}
