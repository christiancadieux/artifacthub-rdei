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
	"strconv"
	"sync"
	"time"
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

const (
	SIDNAME      = "rdeisid"
	TOK_LEN      = 36
	SZ1          = 84
	SZ2          = 40
	LSID_LEN     = 72
	LSID_KEY     = "9adcw0b853e95b8e"
	LSID_MAX_MIN = 60 * 20
	ID_SIZE      = 36
)

func GetLSIDKey() string {
	k := os.Getenv("LSID_KEY")
	if k != "" {
		return k
	}
	return LSID_KEY
}

func LSID(text string) (string, error) {
	text, err := Decrypt([]byte(GetLSIDKey()), text)
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
	fmt.Println("LSID AGE=", now-val, "seconds")
	return text[0:ID_SIZE], nil
}

func Decrypt(key []byte, cryptoText string) (string, error) {
	ciphertext, _ := base64.URLEncoding.DecodeString(cryptoText)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)

	return fmt.Sprintf("%s", ciphertext), nil
}

func validate(rdeiSessionId string) (string, error) {

	if len(rdeiSessionId) < LSID_LEN {
		return "", fmt.Errorf("Invalid session length")
	}
	userId, err := LSID(rdeiSessionId)
	fmt.Println("validate userid=", userId)
	if err != nil {
		return "", err
	}
	return userId, nil
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

var SpecCache = map[string]*RdeiUserSpec{}
var SpecCacheLock sync.Mutex

func saveCacheSpec(rdeiUserId string, spec *RdeiUserSpec) {
	SpecCacheLock.Lock()
	defer SpecCacheLock.Unlock()
	SpecCache[rdeiUserId] = spec
}

func saveCacheUserId(rdeiUserId, userId string) {
	SpecCacheLock.Lock()
	defer SpecCacheLock.Unlock()
	if _, ok := SpecCache[rdeiUserId]; ok {
		SpecCache[rdeiUserId].UserId = userId
	}
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
	UserId      string `json:"userId"`
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
	fmt.Println("getUserName url=", url)
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

	return out.Spec, nil

}

func setCookie(w http.ResponseWriter, name, value string) {
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
		fmt.Printf("setCookie %s=%s \n", SIDNAME, rdeiSessionId)
		setCookie(w, SIDNAME, rdeiSessionId)
		createSession = true
	} else {
		idCookie, err := r.Cookie(SIDNAME)
		if err == nil {
			rdeiSessionId = idCookie.Value
			fmt.Println("Read Cookie", rdeiSessionId)
		} else {
			fmt.Println("FAILED TO READ COOKIE", err)
			if os.Getenv("RDEI_TENANT_LOCK") == "Y" {
				return "", "", fmt.Errorf("SessionID required")
			}
		}
	}
	userID := ""
	if rdeiSessionId != "" {
		rdeiUserId, err := validate(rdeiSessionId)
		fmt.Println("After validate, rdeiUserId=", rdeiUserId)
		if err != nil {
			return "", "", err
		}
		userSpec := getCacheSpec(rdeiUserId)
		if userSpec == nil {
			fmt.Println("Calling getUserName with", rdeiUserId)
			spec1, err := getUserName(rdeiUserId)
			if err != nil {
				return "", "", fmt.Errorf("Failed getUserName - %v", err)
			}
			fmt.Printf("Saving %s in cache \n", rdeiUserId)
			saveCacheSpec(rdeiUserId, spec1)
			userSpec = spec1
		} else {
			fmt.Println("Got the cache for ", rdeiUserId)
		}
		if userSpec != nil && userSpec.UserId != "" {
			fmt.Println("USing userSpec.UserId")
			userID = userSpec.UserId
			err = nil
		} else {
			userID, err = userManager.GetUserIDFromAlias(r.Context(), userSpec.UserName)
		}
		if err != nil {
			fmt.Println("GetUserFromAlias=", err)
			if err := userManager.AddUser(r.Context(), rdeiUserId, userSpec.UserName, userSpec.Email, userSpec.DisplayName); err != nil {
				return "", "", fmt.Errorf("Failed AddUser - %v", err)
			}
			userID, err = userManager.GetUserIDFromAlias(r.Context(), userSpec.UserName)
			if err != nil {
				return "", "", fmt.Errorf("Failed GetUserFromAlias - %v", err)
			}
		}
		saveCacheUserId(rdeiUserId, userID)
		fmt.Printf("userManager.GetUsreID userName=%s, artifactUserID=%s \n", userSpec.UserName, userID)

	}
	if userID != "" && createSession {
		_, err := r.Cookie(sessionCookieName)
		if err != nil || os.Getenv("NEW_SESSION") == "Y" {
			session := h.setSessionCookie(w, r, userID)
			fmt.Println("NEW SESSION=", session.SessionID)
		}
	}
	return userID, rdeiSessionId, nil
}
