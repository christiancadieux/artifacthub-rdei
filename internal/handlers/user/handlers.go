package user

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"google.golang.org/api/people/v1"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/artifacthub/hub/internal/handlers/helpers"
	"github.com/artifacthub/hub/internal/hub"
	"github.com/artifacthub/hub/internal/user"
	"github.com/google/go-github/github"
	"github.com/gorilla/securecookie"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/satori/uuid"
	"github.com/spf13/viper"
	pwvalidator "github.com/wagslane/go-password-validator"
	"golang.org/x/oauth2"
	oagithub "golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
)

const (
	// APIKeyIDHeader represents the header used to provide an API key ID.
	APIKeyIDHeader = "X-API-KEY-ID" // #nosec

	// APIKeySecretHeader represents the header used to provide an API key
	// secret.
	APIKeySecretHeader = "X-API-KEY-SECRET" // #nosec

	// SessionApprovedHeader represents the header used to indicate a client if
	// a session is approved or not. When a user has enabled TFA, sessions need
	// be approved by providing a TFA passcode to the session validation
	// endpoint. If TFA is not enabled, sessions will be approved on creation.
	SessionApprovedHeader = "X-SESSION-APPROVED"

	sessionCookieName    = "sid"
	oauthStateCookieName = "oas"
	sessionDuration      = 30 * 24 * time.Hour
	oauthFailedURL       = "/oauth-failed"
)

var (
	// errInvalidAPIKey error indicates that the API key provided is not valid.
	errInvalidAPIKey = errors.New("invalid api key")

	// errInvalidSession error indicates that the session provided is not valid.
	errInvalidSession = errors.New("invalid session")
)

// Handlers represents a group of http handlers in charge of handling
// users operations.
type Handlers struct {
	userManager   hub.UserManager
	apiKeyManager hub.APIKeyManager
	cfg           *viper.Viper
	sc            *securecookie.SecureCookie
	oauthConfig   map[string]*oauth2.Config
	// oidcProvider  *oidc.Provider
	logger zerolog.Logger
}

// NewHandlers creates a new Handlers instance.
func NewHandlers(
	ctx context.Context,
	userManager hub.UserManager,
	apiKeyManager hub.APIKeyManager,
	cfg *viper.Viper,
) (*Handlers, error) {
	// Setup secure cookie instance
	sc := securecookie.New([]byte(cfg.GetString("server.cookie.hashKey")), nil)
	sc.MaxAge(int(sessionDuration.Seconds()))

	// Setup oauth providers configuration
	oauthConfig := make(map[string]*oauth2.Config)
	// var oidcProvider *oidc.Provider
	for provider := range cfg.GetStringMap("server.oauth") {
		baseCfgKey := fmt.Sprintf("server.oauth.%s.", provider)
		var endpoint oauth2.Endpoint
		switch provider {
		case "github":
			endpoint = oagithub.Endpoint
		case "google":
			endpoint = google.Endpoint
		case "oidc":
			// issuerURL := cfg.GetString(baseCfgKey + "issuerURL")
			// var err error
			// oidcProvider, err = oidc.NewProvider(ctx, issuerURL)
			// if err != nil {
			// 	return nil, fmt.Errorf("error setting up oidc provider: %w", err)
			// }
			// endpoint = oidcProvider.Endpoint()
		default:
			continue
		}
		oauthConfig[provider] = &oauth2.Config{
			ClientID:     cfg.GetString(baseCfgKey + "clientID"),
			ClientSecret: cfg.GetString(baseCfgKey + "clientSecret"),
			Endpoint:     endpoint,
			Scopes:       cfg.GetStringSlice(baseCfgKey + "scopes"),
			RedirectURL:  cfg.GetString(baseCfgKey + "redirectURL"),
		}
	}

	return &Handlers{
		userManager:   userManager,
		apiKeyManager: apiKeyManager,
		cfg:           cfg,
		sc:            sc,
		oauthConfig:   oauthConfig,
		// oidcProvider:  oidcProvider,
		logger: log.With().Str("handlers", "user").Logger(),
	}, nil
}

// ApproveSession is an http handler used to approve a session. When a user has
// enabled TFA, sessions created after users identify themselves with their
// credentials need to be approved to make them valid by providing a valid TFA
// passcode.
func (h *Handlers) ApproveSession(w http.ResponseWriter, r *http.Request) {
	// Get passcode from input
	fmt.Println("Approve Session")
	var input map[string]string
	err := json.NewDecoder(r.Body).Decode(&input)
	if err != nil || input["passcode"] == "" {
		h.logger.Error().Err(err).Str("method", "ApproveSession").Msg(hub.ErrInvalidInput.Error())
		helpers.RenderErrorJSON(w, hub.ErrInvalidInput)
		return
	}
	passcode := input["passcode"]

	// Extract sessionID from cookie
	var sessionID string
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		h.logger.Error().Err(err).Str("method", "ApproveSession").Msg("session cookie not found")
		helpers.RenderErrorWithCodeJSON(w, errInvalidSession, http.StatusUnauthorized)
		return
	}
	if err = h.sc.Decode(sessionCookieName, cookie.Value, &sessionID); err != nil {
		h.logger.Error().Err(err).Str("method", "ApproveSession").Msg("sessionID decoding failed")
		helpers.RenderErrorWithCodeJSON(w, errInvalidSession, http.StatusUnauthorized)
		return
	}

	// Approve session using the passcode provided
	if err := h.userManager.ApproveSession(r.Context(), sessionID, passcode); err != nil {
		h.logger.Error().Err(err).Str("method", "ApproveSession").Send()
		helpers.RenderErrorJSON(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// BasicAuth is a middleware that provides basic auth support.
func (h *Handlers) BasicAuth(next http.Handler) http.Handler {

	validUser := []byte(h.cfg.GetString("server.basicAuth.username"))
	validPass := []byte(h.cfg.GetString("server.basicAuth.password"))
	realm := h.cfg.GetString("theme.siteName")
	fmt.Println("Basic Auth")
	areCredentialsValid := func(user, pass []byte) bool {
		if subtle.ConstantTimeCompare(user, validUser) != 1 {
			return false
		}
		if subtle.ConstantTimeCompare(pass, validPass) != 1 {
			return false
		}
		return true
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || !areCredentialsValid([]byte(user), []byte(pass)) {
			w.Header().Set("WWW-Authenticate", "Basic realm="+realm+`"`)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, "Unauthorized\n")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// CheckPasswordStrength is an http handler that checks the strength of the
// password provided
func (h *Handlers) CheckPasswordStrength(w http.ResponseWriter, r *http.Request) {
	var input map[string]string
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.logger.Error().Err(err).Str("method", "CheckPasswordStrength").Msg(hub.ErrInvalidInput.Error())
		helpers.RenderErrorJSON(w, hub.ErrInvalidInput)
		return
	}
	if err := pwvalidator.Validate(input["password"], user.PasswordMinEntropyBits); err != nil {
		h.logger.Error().Err(err).Str("method", "CheckPasswordStrength").Msg(hub.ErrInvalidInput.Error())
		helpers.RenderErrorWithCodeJSON(w, err, http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// CheckAvailability is an http handler that checks the availability of a given
// value for the provided resource kind.
func (h *Handlers) CheckAvailability(w http.ResponseWriter, r *http.Request) {
	resourceKind := chi.URLParam(r, "resourceKind")
	value := r.FormValue("v")
	w.Header().Set("Cache-Control", helpers.BuildCacheControlHeader(0))
	available, err := h.userManager.CheckAvailability(r.Context(), resourceKind, value)
	if err != nil {
		h.logger.Error().Err(err).Str("method", "CheckAvailability").Send()
		helpers.RenderErrorJSON(w, err)
		return
	}
	if available {
		helpers.RenderErrorWithCodeJSON(w, nil, http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// DeleteUser is an http handler used to delete the account of the user doing
// the request.
func (h *Handlers) DeleteUser(w http.ResponseWriter, r *http.Request) {
	// Delete user
	var input map[string]string
	err := json.NewDecoder(r.Body).Decode(&input)
	if err != nil || input["code"] == "" {
		h.logger.Error().Err(err).Str("method", "DeleteUser").Msg(hub.ErrInvalidInput.Error())
		helpers.RenderErrorJSON(w, hub.ErrInvalidInput)
		return
	}
	if err := h.userManager.DeleteUser(r.Context(), input["code"]); err != nil {
		h.logger.Error().Err(err).Str("method", "DeleteUser").Send()
		if errors.Is(err, user.ErrInvalidDeleteUserCode) {
			helpers.RenderErrorWithCodeJSON(w, err, http.StatusBadRequest)
		} else {
			helpers.RenderErrorJSON(w, err)
		}
		return
	}

	// Request browser to delete session cookie
	cookie := &http.Cookie{
		Name:    sessionCookieName,
		Path:    "/",
		Expires: time.Now().Add(-24 * time.Hour),
	}
	http.SetCookie(w, cookie)
	w.WriteHeader(http.StatusNoContent)
}

// DisableTFA is an http handler used to disable two-factor authentication.
func (h *Handlers) DisableTFA(w http.ResponseWriter, r *http.Request) {
	var input map[string]string
	err := json.NewDecoder(r.Body).Decode(&input)
	if err != nil || input["passcode"] == "" {
		h.logger.Error().Err(err).Str("method", "DisableTFA").Msg(hub.ErrInvalidInput.Error())
		helpers.RenderErrorJSON(w, hub.ErrInvalidInput)
		return
	}
	if err := h.userManager.DisableTFA(r.Context(), input["passcode"]); err != nil {
		h.logger.Error().Err(err).Str("method", "DisableTFA").Send()
		helpers.RenderErrorJSON(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// EnableTFA is an http handler used to enable two-factor authentication.
func (h *Handlers) EnableTFA(w http.ResponseWriter, r *http.Request) {
	var input map[string]string
	err := json.NewDecoder(r.Body).Decode(&input)
	if err != nil || input["passcode"] == "" {
		h.logger.Error().Err(err).Str("method", "EnableTFA").Msg(hub.ErrInvalidInput.Error())
		helpers.RenderErrorJSON(w, hub.ErrInvalidInput)
		return
	}
	if err := h.userManager.EnableTFA(r.Context(), input["passcode"]); err != nil {
		h.logger.Error().Err(err).Str("method", "EnableTFA").Send()
		helpers.RenderErrorJSON(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GetProfile is an http handler used to get a logged in user profile.
func (h *Handlers) GetProfile(w http.ResponseWriter, r *http.Request) {
	fmt.Println("CALLING GetProfile")
	dataJSON, err := h.userManager.GetProfileJSON(r.Context())
	if err != nil {
		h.logger.Error().Err(err).Str("method", "GetProfile").Send()
		helpers.RenderErrorJSON(w, err)
		return
	}
	helpers.RenderJSON(w, dataJSON, 0, http.StatusOK)
}

const (
	SIDNAME = "rdei_sid"
)

func setCookie(w http.ResponseWriter, name, value string) {
	dur := os.Getenv("SESSION_MINS")
	dur_m := int64(60)
	if dur != "" {
		v, err := strconv.ParseInt(dur, 10, 32)
		if err == nil {
			dur_m = v
		}
	}
	expiration := time.Now().Add(time.Duration(dur_m) * time.Minute)
	cookie := http.Cookie{Name: name, Value: value, Expires: expiration, Path: "/"}
	http.SetCookie(w, &cookie)
	log.Print(cookie)
}

// InjectUserID is a middleware that injects the id of the user doing the
// request into the request context when a valid session id is provided.
func (h *Handlers) InjectUserID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var userID string

		// Inject userID in context if available and call next handler
		defer func() {
			if userID != "" {
				ctx := context.WithValue(r.Context(), hub.UserIDKey, userID)
				next.ServeHTTP(w, r.WithContext(ctx))
			} else {
				next.ServeHTTP(w, r)
			}
		}()

		// Extract and validate cookie from request
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			return
		}
		fmt.Println()
		var sessionID string
		if err = h.sc.Decode(sessionCookieName, cookie.Value, &sessionID); err != nil {
			return
		}

		// Check the session provided is valid
		checkSessionOutput, err := h.userManager.CheckSession(r.Context(), sessionID, sessionDuration)
		if err != nil {
			return
		}
		if !checkSessionOutput.Valid {
			return
		}

		userID = checkSessionOutput.UserID
	})
}

// Login is an http handler used to log a user in.
func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	// Extract credentials from request
	var input map[string]string
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.logger.Error().Err(err).Str("method", "Add").Msg(hub.ErrInvalidInput.Error())
		helpers.RenderErrorJSON(w, hub.ErrInvalidInput)
		return
	}

	// Check if the credentials provided are valid
	fmt.Println("CALLING CheckCredentials", input["email"])
	checkCredentialsOutput, err := h.userManager.CheckCredentials(r.Context(), input["email"], input["password"])
	if err != nil {
		h.logger.Error().Err(err).Str("method", "Login").Msg("checkCredentials failed")
		helpers.RenderErrorJSON(w, err)
		return
	}
	/* if !checkCredentialsOutput.Valid {
		helpers.RenderErrorWithCodeJSON(w, nil, http.StatusUnauthorized)
		return
	} CC */

	// Register user session
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	session, err := h.userManager.RegisterSession(r.Context(), &hub.Session{
		UserID:    checkCredentialsOutput.UserID,
		IP:        ip,
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		h.logger.Error().Err(err).Str("method", "Login").Msg("registerSession failed")
		helpers.RenderErrorJSON(w, err)
		return
	}

	// Generate and set session cookie
	encodedSessionID, err := h.sc.Encode(sessionCookieName, session.SessionID)
	if err != nil {
		h.logger.Error().Err(err).Str("method", "Login").Msg("sessionID encoding failed")
		helpers.RenderErrorJSON(w, err)
		return
	}
	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    encodedSessionID,
		Path:     "/",
		Expires:  time.Now().Add(sessionDuration),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if h.cfg.GetBool("server.cookie.secure") {
		cookie.Secure = true
	}
	http.SetCookie(w, cookie)
	w.Header().Set(SessionApprovedHeader, strconv.FormatBool(session.Approved))
	w.WriteHeader(http.StatusNoContent)
}

// Logout is an http handler used to log a user out.
func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	// Delete user session
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		var sessionID string
		err = h.sc.Decode(sessionCookieName, cookie.Value, &sessionID)
		if err == nil {
			err = h.userManager.DeleteSession(r.Context(), sessionID)
			if err != nil {
				h.logger.Error().Err(err).Str("method", "Logout").Msg("deleteSession failed")
			}
		}
	}

	// Request browser to delete session cookie
	cookie = &http.Cookie{
		Name:    sessionCookieName,
		Path:    "/",
		Expires: time.Now().Add(-24 * time.Hour),
	}
	http.SetCookie(w, cookie)
	w.WriteHeader(http.StatusNoContent)
}

// OauthCallback is an http handler in charge of completing the oauth
// authentication process, registering the user if needed.
func (h *Handlers) OauthCallback(w http.ResponseWriter, r *http.Request) {
	logger := h.logger.With().Str("method", "OauthCallback").Logger()
	fmt.Println("CALLING OauthCallback")
	// Validate oauth code and state
	code := r.FormValue("code")
	if code == "" {
		logger.Error().Msg("oauth code not provided")
		http.Redirect(w, r, oauthFailedURL, http.StatusSeeOther)
		return
	}
	state, err := NewOauthState(r.FormValue("state"))
	if err != nil {
		logger.Error().Msg("oauth state not provided")
		http.Redirect(w, r, oauthFailedURL, http.StatusSeeOther)
		return
	}
	stateCookie, err := r.Cookie(oauthStateCookieName)
	if err != nil {
		logger.Error().Err(err).Msg("state cookie not provided")
		http.Redirect(w, r, oauthFailedURL, http.StatusSeeOther)
		return
	}
	if state.Random != stateCookie.Value {
		logger.Error().Err(err).Msg("invalid state cookie")
		http.Redirect(w, r, oauthFailedURL, http.StatusSeeOther)
		return
	}
	stateCookie = &http.Cookie{
		Name:    oauthStateCookieName,
		Path:    "/",
		Expires: time.Now().Add(-24 * time.Hour),
	}
	http.SetCookie(w, stateCookie)

	// Register user if needed, or return his id if already registered
	provider := chi.URLParam(r, "provider")
	providerConfig := h.oauthConfig[provider]
	oauthToken, err := providerConfig.Exchange(r.Context(), code)
	if err != nil {
		logger.Error().Err(err).Msg("oauth code exchange failed")
		http.Redirect(w, r, oauthFailedURL, http.StatusSeeOther)
		return
	}
	userID, err := h.registerUserWithOauth(r.Context(), provider, providerConfig, oauthToken)
	if err != nil {
		logger.Error().Err(err).Msg("oauth code exchange failed")
		http.Redirect(w, r, oauthFailedURL, http.StatusSeeOther)
		return
	}

	// Register user session and set session cookie
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	session, err := h.userManager.RegisterSession(r.Context(), &hub.Session{
		UserID:    userID,
		IP:        ip,
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		logger.Error().Err(err).Msg("registerSession failed")
		http.Redirect(w, r, oauthFailedURL, http.StatusSeeOther)
		return
	}
	encodedSessionID, err := h.sc.Encode(sessionCookieName, session.SessionID)
	if err != nil {
		logger.Error().Err(err).Msg("sessionID encoding failed")
		http.Redirect(w, r, oauthFailedURL, http.StatusSeeOther)
		return
	}
	sessionCookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    encodedSessionID,
		Path:     "/",
		Expires:  time.Now().Add(sessionDuration),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if h.cfg.GetBool("server.cookie.secure") {
		sessionCookie.Secure = true
	}
	http.SetCookie(w, sessionCookie)
	http.Redirect(w, r, state.RedirectURL, http.StatusSeeOther)
}

// OauthRedirect is an http handler that redirects the user to the oauth
// provider to proceed with the authorization.
func (h *Handlers) OauthRedirect(w http.ResponseWriter, r *http.Request) {
	// Generate random value for oauth session and store it in browser. It'll
	// be used later to validate the callback request is done by the same user.
	random := uuid.NewV4().String()
	cookie := &http.Cookie{
		Name:     oauthStateCookieName,
		Value:    random,
		Path:     "/",
		HttpOnly: true,
	}
	if h.cfg.GetBool("server.cookie.secure") {
		cookie.Secure = true
	}
	http.SetCookie(w, cookie)

	// Prepare oauth state and redirect user to oauth provider
	redirectURL := r.FormValue("redirect_url")
	if redirectURL == "" {
		redirectURL = r.Referer()
	}
	if redirectURL == "" {
		redirectURL = "/"
	}
	providerConfig := h.oauthConfig[chi.URLParam(r, "provider")]
	state := &OauthState{
		Random:      random,
		RedirectURL: redirectURL,
	}
	authCodeURL := providerConfig.AuthCodeURL(state.String())
	http.Redirect(w, r, authCodeURL, http.StatusSeeOther)
}

// RegisterDeleteUserCode is an http handler used to register a code to
// delete a user account. The code will be emailed to the address provided.
func (h *Handlers) RegisterDeleteUserCode(w http.ResponseWriter, r *http.Request) {
	err := h.userManager.RegisterDeleteUserCode(r.Context())
	if err != nil {
		h.logger.Error().Err(err).Str("method", "RegisterDeleteUserCode").Send()
		helpers.RenderErrorJSON(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// RegisterPasswordResetCode is an http handler used to register a code to
// reset the password. The code will be emailed to the address provided.
func (h *Handlers) RegisterPasswordResetCode(w http.ResponseWriter, r *http.Request) {
	var input map[string]string
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.logger.Error().Err(err).Str("method", "RegisterPasswordResetCode").Msg(hub.ErrInvalidInput.Error())
		helpers.RenderErrorJSON(w, hub.ErrInvalidInput)
		return
	}
	_ = h.userManager.RegisterPasswordResetCode(r.Context(), input["email"])
	w.WriteHeader(http.StatusCreated)
}

// RegisterUser is an http handler used to register a user in the hub database.
func (h *Handlers) RegisterUser(w http.ResponseWriter, r *http.Request) {
	fmt.Println("CALLING RegisterUser")
	if !h.cfg.GetBool("server.allowUserSignUp") {
		h.logger.Error().Msg("New users sign up is disabled")
		helpers.RenderErrorWithCodeJSON(w, nil, http.StatusForbidden)
		return
	}

	u := &hub.User{}
	err := json.NewDecoder(r.Body).Decode(&u)
	if err != nil {
		h.logger.Error().Err(err).Str("method", "RegisterUser").Msg("invalid user")
		helpers.RenderErrorJSON(w, hub.ErrInvalidInput)
		return
	}
	u.EmailVerified = false
	if u.Password == "" {
		errMsg := "password not provided"
		h.logger.Error().Err(err).Str("method", "RegisterUser").Msg(errMsg)
		helpers.RenderErrorJSON(w, fmt.Errorf("%w: %s", hub.ErrInvalidInput, errMsg))
		return
	}
	err = h.userManager.RegisterUser(r.Context(), u)
	if err != nil {
		h.logger.Error().Err(err).Str("method", "RegisterUser").Send()
		helpers.RenderErrorJSON(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// registerUserWithOauth is a helper function that registers a user using the
// details from his oauth provider if he's not already registered, returning
// the user id.
func (h *Handlers) registerUserWithOauth(
	ctx context.Context,
	provider string,
	providerConfig *oauth2.Config,
	oauthToken *oauth2.Token,
) (string, error) {
	// Build user from profile from oauth provider
	var u *hub.User
	var err error
	switch provider {
	case "github":
		u, err = h.newUserFromGitHubProfile(ctx, oauthToken)
	case "google":
		u, err = h.newUserFromGoogleProfile(ctx, providerConfig, oauthToken)
	case "oidc":
		u, err = h.newUserFromOIDProfile(ctx, oauthToken)
	default:
		err = fmt.Errorf("invalid provider: %s", provider)
	}
	if err != nil {
		return "", err
	}

	// Check user alias availability and append suffix to it if needed
	available, err := h.userManager.CheckAvailability(ctx, "userAlias", u.Alias)
	if err != nil {
		return "", err
	}
	if !available {
		randomSuffix, err := getRandomSuffix()
		if err != nil {
			return "", err
		}
		u.Alias += randomSuffix
	}

	// Check if user exists
	userID, err := h.userManager.GetUserID(ctx, u.Email)
	if err != nil && !errors.Is(err, user.ErrNotFound) {
		return "", err
	}

	// Register user if needed
	if userID == "" {
		u.EmailVerified = true
		err := h.userManager.RegisterUser(ctx, u)
		if err != nil {
			return "", err
		}
		userID, err = h.userManager.GetUserID(ctx, u.Email)
		if err != nil {
			return "", err
		}
	}

	return userID, nil
}

// newUserFromGitHubProfile builds a new hub.User instance from the user's
// GitHub profile.
func (h *Handlers) newUserFromGitHubProfile(
	ctx context.Context,
	oauthToken *oauth2.Token,
) (*hub.User, error) {
	// Get user profile and emails
	httpClient := oauth2.NewClient(ctx, oauth2.StaticTokenSource(oauthToken))
	githubClient := github.NewClient(httpClient)
	profile, _, err := githubClient.Users.Get(ctx, "")
	if err != nil {
		return nil, err
	}
	emails, _, err := githubClient.Users.ListEmails(ctx, nil)
	if err != nil {
		return nil, err
	}

	// Get user's primary email and check if it has been verified
	var email string
	for _, entry := range emails {
		if entry.GetPrimary() && entry.GetVerified() {
			email = entry.GetEmail()
		}
	}
	if email == "" {
		return nil, errors.New("no valid email available for use")
	}

	return &hub.User{
		Alias:     profile.GetLogin(),
		Email:     email,
		FirstName: profile.GetName(),
	}, nil
}

// newUserFromGoogleProfile builds a new hub.User instance from the user's
// Google profile.
func (h *Handlers) newUserFromGoogleProfile(
	ctx context.Context,
	providerConfig *oauth2.Config,
	oauthToken *oauth2.Token,
) (*hub.User, error) {
	// Get user profile
	opt := option.WithTokenSource(providerConfig.TokenSource(ctx, oauthToken))
	peopleService, err := people.NewService(ctx, opt)
	if err != nil {
		return nil, err
	}
	profile, err := peopleService.People.
		Get("people/me").
		PersonFields("names,emailAddresses").
		Do()
	if err != nil {
		return nil, err
	}

	// Get user's primary email and check if it has been verified
	var email string
	for _, entry := range profile.EmailAddresses {
		if entry.Metadata.Primary && entry.Metadata.Verified {
			email = entry.Value
		}
	}
	if email == "" {
		return nil, errors.New("no valid email available for use")
	}

	return &hub.User{
		Alias:     strings.Split(email, "@")[0],
		Email:     email,
		FirstName: profile.Names[0].GivenName,
		LastName:  profile.Names[0].FamilyName,
	}, nil
}

// newUserFromOIDProfile builds a new hub.User instance from the user's OpenID
// profile.
func (h *Handlers) newUserFromOIDProfile(
	ctx context.Context,
	oauthToken *oauth2.Token,
) (*hub.User, error) {
	// Extract the id token from oauth token
	rawIDToken, ok := oauthToken.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("id token not available")
	}

	// Parse and verify id token payload
	// verifier := h.oidcProvider.Verifier(&oidc.Config{
	// 	ClientID: h.cfg.GetString("server.oauth.oidc.clientID"),
	// })
	idToken := rawIDToken
	fmt.Println("idtoken=", idToken)
	// idToken, err := verifier.Verify(ctx, rawIDToken)
	// if err != nil {
	// 	return nil, fmt.Errorf("invalid id token: %w", err)
	// }

	// Extract claims
	var claims struct {
		Email             string `json:"email"`
		EmailVerified     bool   `json:"email_verified"`
		GivenName         string `json:"given_name"`
		FamilyName        string `json:"family_name"`
		PreferredUsername string `json:"preferred_username"`
	}
	//if err := idToken.Claims(&claims); err != nil {
	//	return nil, fmt.Errorf("error extracting claims from id token: %w", err)
	//}
	skipEmailVerifiedCheck := h.cfg.GetBool("server.oauth.oidc.skipEmailVerifiedCheck")
	if claims.Email == "" || (!skipEmailVerifiedCheck && !claims.EmailVerified) {
		return nil, errors.New("no valid email available for use")
	}
	alias := claims.PreferredUsername
	if alias == "" {
		alias = strings.Split(claims.Email, "@")[0]
	}

	return &hub.User{
		Alias:     alias,
		Email:     claims.Email,
		FirstName: claims.GivenName,
		LastName:  claims.FamilyName,
	}, nil
}

const (
	TOK_LEN = 36
	SZ1     = 84
	SZ2     = 40
)

func swap(s0 string) string {
	s := []byte(s0)
	i := 1
	for {
		tmp := s[i]
		s[i] = s[SZ1-i]
		s[SZ1-i] = tmp
		i += 3
		if i > SZ2 {
			break
		}
	}
	return string(s)
}

func validate(rdeiSessionId string) (string, string, error) {

	if len(rdeiSessionId) != SZ1 {
		return "", "", fmt.Errorf("Invalid session length")
	}

	tok0 := swap(rdeiSessionId)

	userId := tok0[0:TOK_LEN]
	facId := tok0[TOK_LEN+1 : TOK_LEN*2+1]
	times := tok0[TOK_LEN*2+2:]
	old_i, err := strconv.ParseInt(times, 10, 32)
	if err != nil {
		return "", "", fmt.Errorf(" Invalid session %s", rdeiSessionId)
	}
	now_unix := time.Now().Unix()
	age_sec := now_unix - old_i
	if age_sec/60 > 12*60 {
		return "", "", fmt.Errorf(" Expired session %s", rdeiSessionId)
	}
	return userId, facId, nil
}

var SpecCache = map[string]*RdeiUserSpec{}
var SpecCacheLock sync.Mutex

func saveCacheSpec(userId string, spec *RdeiUserSpec) {
	SpecCacheLock.Lock()
	defer SpecCacheLock.Unlock()
	SpecCache[userId] = spec
}

func getCacheSpec(userId string) *RdeiUserSpec {
	SpecCacheLock.Lock()
	defer SpecCacheLock.Unlock()

	if v, ok := SpecCache[userId]; ok {
		return v
	}
	return nil
}

type RdeiUserSpec struct {
	UserName    string `json:"userName"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
}
type RdeiUser struct {
	Spec *RdeiUserSpec `json:"spec"`
}

func getUserName(userId string) (*RdeiUserSpec, error) {
	url := os.Getenv("RDEI_URL")
	if url == "" {
		url = "https://api.rdei.comcast.net"
	}
	url += "/v1/users/" + userId

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("Error creating Request. %s", err.Error())
	}
	token := os.Getenv("RDEI_TOKEN")
	if token == "" {
		token = "8a9ecc88-c97f-4d18-a78b-d7f13ed408b6"
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	out := &RdeiUser{}
	err = json.Unmarshal(body, &out)
	fmt.Printf("Username=%+v \n", out.Spec.UserName)
	return out.Spec, nil

}

// RequireLogin is a middleware that verifies if a user is logged in.
func (h *Handlers) RequireLogin(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		var userID string

		fmt.Printf("URL=%v, q=%v, raw=%v, rawq=%v \n", r.URL.Path, r.URL.Query(), r.URL.RawPath, r.URL.RawQuery)
		queryValues := r.URL.Query()

		rdeiSessionId := queryValues.Get(SIDNAME)

		if rdeiSessionId != "" {
			fmt.Printf("setCookie %s=%s \n", SIDNAME, rdeiSessionId)
			setCookie(w, SIDNAME, rdeiSessionId)
		} else {
			idCookie, err := r.Cookie(SIDNAME)
			if err == nil {
				rdeiSessionId = idCookie.Value
				fmt.Println("Read Cookie", rdeiSessionId)
			} else {
				fmt.Println("FAILED TO READ COOKIE", err)
				if os.Getenv("RDEI_TENANT_LOCK") == "Y" {
					helpers.RenderErrorWithCodeJSON(w, fmt.Errorf("SessionID required"), http.StatusUnauthorized)
					return
				}
			}
		}

		// Extract API key id and secret from header
		apiKeyID := r.Header.Get(APIKeyIDHeader)
		apiKeySecret := r.Header.Get(APIKeySecretHeader)
		fmt.Println("CALLING RequireLogin HandlerFunc", apiKeyID, apiKeySecret)

		if rdeiSessionId != "" {
			rdeiUserId, _, err := validate(rdeiSessionId)
			if err != nil {
				helpers.RenderErrorWithCodeJSON(w, err, http.StatusUnauthorized)
				return
			}
			userSpec := getCacheSpec(rdeiUserId)
			if userSpec == nil {
				spec1, err := getUserName(rdeiUserId)
				if err != nil {
					helpers.RenderErrorWithCodeJSON(w, fmt.Errorf("Failed getUserName - %v", err), http.StatusUnauthorized)
					return
				}
				fmt.Printf("Saving %s in cache \n", rdeiUserId)
				saveCacheSpec(rdeiUserId, spec1)
				userSpec = spec1
			} else {
				fmt.Println("Got the cache for ", rdeiUserId)
			}

			userID, err = h.userManager.GetUserIDFromAlias(r.Context(), userSpec.UserName)
			if err != nil {
				fmt.Println("GetUserFromAliass=", err)
				if err := h.userManager.AddUser(r.Context(), rdeiUserId, userSpec.UserName, userSpec.Email, userSpec.DisplayName); err != nil {
					helpers.RenderErrorWithCodeJSON(w, fmt.Errorf("Failed AddUser - %v", err), http.StatusUnauthorized)
					return
				}
				userID, err = h.userManager.GetUserIDFromAlias(r.Context(), userSpec.UserName)
				if err != nil {
					helpers.RenderErrorWithCodeJSON(w, fmt.Errorf("Failed GetUserFromAlias - %v", err), http.StatusUnauthorized)
					return
				}
			}
			fmt.Printf("userManager.GetUsreID userName=%s, artifactUserID=%s \n", userSpec.UserName, userID)

		} else if apiKeyID != "" && apiKeySecret != "" {
			// Use API key based authentication if API key is provided
			// Check the API key provided is valid
			checkAPIKeyOutput, err := h.apiKeyManager.Check(r.Context(), apiKeyID, apiKeySecret)
			if err != nil {
				h.logger.Error().Err(err).Str("method", "RequireLogin").Msg("checkAPIKey failed")
				helpers.RenderErrorWithCodeJSON(w, nil, http.StatusInternalServerError)
				return
			}
			if !checkAPIKeyOutput.Valid {
				helpers.RenderErrorWithCodeJSON(w, errInvalidAPIKey, http.StatusUnauthorized)
				return
			}

			userID = checkAPIKeyOutput.UserID
		} else {
			// Use cookie based authentication
			cookie, err := r.Cookie(sessionCookieName)
			if err == nil {
				// Extract and validate cookie from request
				var sessionID string
				if err = h.sc.Decode(sessionCookieName, cookie.Value, &sessionID); err != nil {
					h.logger.Error().Err(err).Str("method", "RequireLogin").Msg("sessionID decoding failed")
					helpers.RenderErrorWithCodeJSON(w, errInvalidSession, http.StatusUnauthorized)
					return
				}

				// Check the session provided is valid
				checkSessionOutput, err := h.userManager.CheckSession(r.Context(), sessionID, sessionDuration)
				fmt.Printf("Cookie=%s, sid=%s \n", cookie.Value, sessionID)

				if err != nil {
					h.logger.Error().Err(err).Str("method", "RequireLogin").Msg("checkSession failed")
					helpers.RenderErrorWithCodeJSON(w, nil, http.StatusInternalServerError)
					return
				} else {
					fmt.Println("SessionID=", checkSessionOutput.UserID)
				}
				if !checkSessionOutput.Valid {
					helpers.RenderErrorWithCodeJSON(w, errInvalidSession, http.StatusUnauthorized)
					return
				}

				userID = checkSessionOutput.UserID
			}
		}

		// Return if no authentication method succeeded
		if userID == "" {
			helpers.RenderErrorWithCodeJSON(w, nil, http.StatusUnauthorized)
			return
		}

		// Inject userID in context and call next handler
		ctx := context.WithValue(r.Context(), hub.UserIDKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ResetPassword is an http handler used to reset the user's password.
func (h *Handlers) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var input map[string]string
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.logger.Error().Err(err).Str("method", "ResetPassword").Msg(hub.ErrInvalidInput.Error())
		helpers.RenderErrorJSON(w, hub.ErrInvalidInput)
		return
	}
	err := h.userManager.ResetPassword(r.Context(), input["code"], input["password"])
	if err != nil {
		h.logger.Error().Err(err).Str("method", "ResetPassword").Send()
		if errors.Is(err, user.ErrInvalidPasswordResetCode) {
			helpers.RenderErrorWithCodeJSON(w, err, http.StatusBadRequest)
		} else {
			helpers.RenderErrorJSON(w, err)
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// SetupTFA is an http handler used to setup two-factor authentication.
func (h *Handlers) SetupTFA(w http.ResponseWriter, r *http.Request) {
	dataJSON, err := h.userManager.SetupTFA(r.Context())
	if err != nil {
		h.logger.Error().Err(err).Str("method", "SetupTFA").Send()
		helpers.RenderErrorJSON(w, err)
		return
	}
	helpers.RenderJSON(w, dataJSON, 0, http.StatusCreated)
}

// UpdatePassword is an http handler used to update the password in the hub
// database.
func (h *Handlers) UpdatePassword(w http.ResponseWriter, r *http.Request) {
	var input map[string]string
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.logger.Error().Err(err).Str("method", "UpdatePassword").Msg(hub.ErrInvalidInput.Error())
		helpers.RenderErrorJSON(w, hub.ErrInvalidInput)
		return
	}
	err := h.userManager.UpdatePassword(r.Context(), input["old"], input["new"])
	if err != nil {
		h.logger.Error().Err(err).Str("method", "UpdatePassword").Send()
		if errors.Is(err, user.ErrInvalidPassword) {
			helpers.RenderErrorWithCodeJSON(w, nil, http.StatusUnauthorized)
		} else {
			helpers.RenderErrorJSON(w, err)
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// UpdateProfile is an http handler used to update the user in the hub database.
func (h *Handlers) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	u := &hub.User{}
	err := json.NewDecoder(r.Body).Decode(&u)
	if err != nil {
		h.logger.Error().Err(err).Str("method", "UpdateUserProfile").Msg("invalid user")
		helpers.RenderErrorJSON(w, hub.ErrInvalidInput)
		return
	}
	err = h.userManager.UpdateProfile(r.Context(), u)
	if err != nil {
		h.logger.Error().Err(err).Str("method", "UpdateUserProfile").Send()
		helpers.RenderErrorJSON(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// VerifyEmail is an http handler used to verify a user's email address.
func (h *Handlers) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var input map[string]string
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.logger.Error().Err(err).Str("method", "VerifyEmail").Msg(hub.ErrInvalidInput.Error())
		helpers.RenderErrorJSON(w, hub.ErrInvalidInput)
		return
	}
	verified, err := h.userManager.VerifyEmail(r.Context(), input["code"])
	if err != nil {
		h.logger.Error().Err(err).Str("method", "VerifyEmail").Send()
		helpers.RenderErrorJSON(w, err)
		return
	}
	if !verified {
		helpers.RenderErrorWithCodeJSON(w, fmt.Errorf("email verification code has expired"), http.StatusGone)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// VerifyPasswordResetCode is an http handler used to verify a reset password
// code.
func (h *Handlers) VerifyPasswordResetCode(w http.ResponseWriter, r *http.Request) {
	var input map[string]string
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.logger.Error().Err(err).Str("method", "VerifyPasswordResetCode").Msg(hub.ErrInvalidInput.Error())
		helpers.RenderErrorJSON(w, hub.ErrInvalidInput)
		return
	}
	err := h.userManager.VerifyPasswordResetCode(r.Context(), input["code"])
	if err != nil {
		h.logger.Error().Err(err).Str("method", "VerifyPasswordResetCode").Send()
		if errors.Is(err, user.ErrInvalidPasswordResetCode) {
			helpers.RenderErrorWithCodeJSON(w, err, http.StatusGone)
		} else {
			helpers.RenderErrorJSON(w, err)
		}
		return
	}
	w.WriteHeader(http.StatusOK)
}

// OauthState represents the state of an oauth authorization session, used to
// increase the security of the process and to restore the state of the
// application.
type OauthState struct {
	Random      string
	RedirectURL string
}

// String returns an OauthState instance as a string.
func (s *OauthState) String() string {
	dataJSON, _ := json.Marshal(s)
	return base64.StdEncoding.EncodeToString(dataJSON)
}

// NewOauthState creates a new OauthState instance from the string
// representation provided.
func NewOauthState(s string) (*OauthState, error) {
	dataJSON, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	var state *OauthState
	if err := json.Unmarshal(dataJSON, &state); err != nil {
		return nil, err
	}
	return state, nil
}

// getRandomSuffix is a helper function that returns a random numerical suffix
// to be used in user aliases when the selected alias is already taken.
func getRandomSuffix() (string, error) {
	nBig, err := rand.Int(rand.Reader, big.NewInt(1000))
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(nBig.Int64(), 10), nil
}
