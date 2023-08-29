package user

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/artifacthub/hub/internal/hub"
	"github.com/rs/zerolog/log"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"
)

const (
	SIDNAME      = "rdeisid"
	TOK_LEN      = 36
	SZ1          = 84
	SZ2          = 40
	LSID_LEN     = 72
	LSID_KEY     = "9adcw0b853e95b8e"
	LSID_MAX_MIN = 60 * 20
	ID_SIZE      = 36
	// saving 5 keys means that if the keys are rotated every hour, an old key could still work for 6 hours
	// unless this server is re-started.
	KEYS_SIZE = 5
	LOG       = true
)

func logit(s string, args ...any) {
	if LOG {
		fmt.Printf(s+"\n", args...)
	}

}

type RdeiManager struct {
	sync.Mutex
	SpecCache map[string]*RdeiUserSpec
	Keys      []string
}

var rdeiMgr = newRdeiManager()

func newRdeiManager() *RdeiManager {
	mgr := RdeiManager{}
	mgr.SpecCache = map[string]*RdeiUserSpec{}
	mgr.Keys = []string{}
	for i := 0; i < KEYS_SIZE; i++ {
		mgr.Keys = append(mgr.Keys, LSID_KEY)
	}

	refresh_freq := os.Getenv("LSID_KEY_FREQ")
	if refresh_freq == "" {
		return &mgr
	}

	freq, err := strconv.ParseInt(refresh_freq, 10, 32)
	if err != nil {
		freq = 1
	}
	logit("LSID key Refresh frequency: %d minutes ", freq)
	go mgr.Refresh(freq)
	return &mgr
}

func (m *RdeiManager) Refresh(freq int64) {
	ticker := time.NewTicker(time.Duration(freq) * time.Minute)
	defer ticker.Stop()
	m.fetchNewKey()
	for {
		select {
		case <-ticker.C:
			m.fetchNewKey()
		}
	}
}

func (m *RdeiManager) getKey(ix int) []byte {
	m.Lock()
	defer m.Unlock()

	return []byte(m.Keys[ix])
}

func (m *RdeiManager) fetchNewKey() {
	tries := 0
	var key string
	var err error
	for {
		tries++
		key, err = m.getLsidKey()
		if err == nil {
			break
		}
		logit("fetchNewKey failed try= %d ", tries)
		if tries > 5 {
			logit("failed getNewKey - %v", err)
			return
		}
	}
	logit("FETCH NEW KEY %s", key)
	m.Lock()
	defer m.Unlock()

	if key != m.Keys[KEYS_SIZE-1] {
		for i := 0; i < KEYS_SIZE-1; i++ {
			m.Keys[i] = m.Keys[i+1]
		}
		m.Keys[KEYS_SIZE-1] = key
	}
	logit("Keys fetched = %+v ", m.Keys)
}

// var SpecCache = map[string]*RdeiUserSpec{}
// var SpecCacheLock sync.Mutex

func (m *RdeiManager) LSID(text string) (string, error) {
	text, err := m.Decrypt(text)
	if err != nil {
		return "", err
	}
	ts := text[ID_SIZE+1:]
	val, err := strconv.ParseInt(ts, 10, 32)
	if err != nil {
		return "", err
	}
	now := time.Now().Unix()

	if now-val > LSID_MAX_MIN*60 {
		return "", fmt.Errorf("Expired LSID")
	}
	logit("LSID AGE= %d seconds", now-val)
	return text[0:ID_SIZE], nil
}

func (m *RdeiManager) isUUID(uuid string) bool {
	r := regexp.MustCompile("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}")
	return r.MatchString(uuid)
}

func (m *RdeiManager) Decrypt(cryptoText string) (string, error) {

	ciphertext, _ := base64.URLEncoding.DecodeString(cryptoText)
	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	// try most recent and maybe previous key until a valid uuid is detected
	for ix := KEYS_SIZE - 1; ix >= 0; ix-- {
		key := m.getKey(ix)
		logit("Decrypt using new key %d - %s", ix, string(key))
		block, err := aes.NewCipher(key)
		if err != nil {
			return "", err
		}

		ciphertext2 := make([]byte, len(ciphertext))
		copy(ciphertext2, ciphertext)

		iv := ciphertext2[:aes.BlockSize]
		ciphertext2 = ciphertext2[aes.BlockSize:]

		stream := cipher.NewCFBDecrypter(block, iv)
		// XORKeyStream can work in-place if the two arguments are the same.
		stream.XORKeyStream(ciphertext2, ciphertext2)

		rc := fmt.Sprintf("%s", ciphertext2)

		if m.isUUID(rc) {
			logit("Success Decrypting using key %d =%s ", ix, string(key))
			return rc, nil
		} else {
			logit("Decrypt Failed - not UUID - key %d", ix)
		}
	}
	logit("Decrypt: Valid UUID not found")
	return "", fmt.Errorf("valid UUID not found")
}

func (m *RdeiManager) validate(rdeiSessionId string) (string, error) {

	if len(rdeiSessionId) < LSID_LEN {
		return "", fmt.Errorf("Invalid session length")
	}
	userId, err := m.LSID(rdeiSessionId)
	logit("validate userid= %s ", userId)
	if err != nil {
		return "", err
	}
	return userId, nil
}

func (m *RdeiManager) saveCacheSpec(rdeiUserId string, spec *RdeiUserSpec) {
	m.Lock()
	defer m.Unlock()
	m.SpecCache[rdeiUserId] = spec
}

func (m *RdeiManager) saveCacheUserId(rdeiUserId, userId string) {
	m.Lock()
	defer m.Unlock()
	if _, ok := m.SpecCache[rdeiUserId]; ok {
		m.SpecCache[rdeiUserId].UserId = userId
	}
}

func (m *RdeiManager) getCacheSpec(userId string) *RdeiUserSpec {
	m.Lock()
	defer m.Unlock()

	if v, ok := m.SpecCache[userId]; ok {
		return v
	}
	return nil
}

type RdeiUserSpec struct {
	UserName    string `json:"userName"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	UserId      string `json:"userId"`
}
type RdeiUser struct {
	Spec *RdeiUserSpec `json:"spec"`
}

func (m *RdeiManager) rdeiUrl() string {
	url := os.Getenv("RDEI_URL")
	if url == "" {
		url = "https://api.rdei.comcast.net"
	}
	return url
}

func (m *RdeiManager) rdeiToken() string {
	token := os.Getenv("RDEI_TOKEN")
	if token == "" {
		token = "8a9ecc88-c97f-4d18-a78b-d7f13ed408b6"
	}
	return token
}

func (m *RdeiManager) getUserName(userId string) (*RdeiUserSpec, error) {

	url := m.rdeiUrl() + "/v1/users/" + userId
	logit("getUserName url= %s ", url)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("Error creating Request. %s", err.Error())
	}
	token := m.rdeiToken()
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

	return out.Spec, nil
}

type lsidKey struct {
	Key string `json:"key"`
}

func (m *RdeiManager) getLsidKey() (string, error) {

	url := m.rdeiUrl() + "/v1/lsid"
	logit("getLsidKey url= %s ", url)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("Error creating Request. %s", err.Error())
	}
	token := m.rdeiToken()
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	out := &lsidKey{}
	err = json.Unmarshal(body, &out)

	return out.Key, nil
}

func (m *RdeiManager) setCookie(w http.ResponseWriter, name, value string) {
	dur := os.Getenv("SESSION_HOURS")
	dur_h := int64(24)
	if dur != "" {
		v, err := strconv.ParseInt(dur, 10, 32)
		if err == nil {
			dur_h = v
		}
	}
	expiration := time.Now().Add(time.Duration(dur_h) * time.Hour)
	cookie := http.Cookie{Name: name, Value: value, Expires: expiration, Path: "/"}
	http.SetCookie(w, &cookie)
	log.Print(cookie)
}

func (h *Handlers) rdeiSaveSID(w http.ResponseWriter, r *http.Request, userManager hub.UserManager) (string, string, error) {
	queryValues := r.URL.Query()

	rdeiSessionId := queryValues.Get(SIDNAME)
	createSession := false
	if rdeiSessionId != "" {
		logit("setCookie %s=%s ", SIDNAME, rdeiSessionId)
		rdeiMgr.setCookie(w, SIDNAME, rdeiSessionId)
		createSession = true
	} else {
		idCookie, err := r.Cookie(SIDNAME)
		if err == nil {
			rdeiSessionId = idCookie.Value
			logit("Read Cookie", rdeiSessionId)
		} else {
			logit("FAILED TO READ COOKIE", err)
			if os.Getenv("RDEI_TENANT_LOCK") == "Y" {
				return "", "", fmt.Errorf("SessionID required")
			}
		}
	}
	userID := ""
	if rdeiSessionId != "" {
		rdeiUserId, err := rdeiMgr.validate(rdeiSessionId)
		logit("After validate, rdeiUserId=%s", rdeiUserId)
		if err != nil {
			return "", "", err
		}
		userSpec := rdeiMgr.getCacheSpec(rdeiUserId)
		if userSpec == nil {
			logit("Calling getUserName with %s ", rdeiUserId)
			spec1, err := rdeiMgr.getUserName(rdeiUserId)
			if err != nil {
				return "", "", fmt.Errorf("Failed getUserName - %v", err)
			}
			logit("Saving %s in cache ", rdeiUserId)
			rdeiMgr.saveCacheSpec(rdeiUserId, spec1)
			userSpec = spec1
		} else {
			logit("Got the cache for  %s ", rdeiUserId)
		}
		if userSpec != nil && userSpec.UserId != "" {
			logit("USing userSpec.UserId ")
			userID = userSpec.UserId
			err = nil
		} else {
			userID, err = userManager.GetUserIDFromAlias(r.Context(), userSpec.UserName)
		}
		if err != nil {
			logit("GetUserFromAlias= %v ", err)
			if err := userManager.AddUser(r.Context(), rdeiUserId, userSpec.UserName, userSpec.Email, userSpec.DisplayName); err != nil {
				return "", "", fmt.Errorf("Failed AddUser - %v", err)
			}
			userID, err = userManager.GetUserIDFromAlias(r.Context(), userSpec.UserName)
			if err != nil {
				return "", "", fmt.Errorf("Failed GetUserFromAlias - %v", err)
			}
		}
		rdeiMgr.saveCacheUserId(rdeiUserId, userID)
		logit("userManager.GetUsreID userName=%s, artifactUserID=%s ", userSpec.UserName, userID)

	}
	if userID != "" && createSession {
		_, err := r.Cookie(sessionCookieName)
		if err != nil || os.Getenv("NEW_SESSION") == "Y" {
			session := h.setSessionCookie(w, r, userID)
			logit("NEW SESSION= %s ", session.SessionID)
		}
	}
	return userID, rdeiSessionId, nil
}

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

func validate0(rdeiSessionId string) (string, string, error) {

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
