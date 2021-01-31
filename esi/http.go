package esi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-redis/redis/v7"
	"github.com/sethgrid/pester"
)

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

type HTTPHelp struct {
	redis  *redis.Client
	client *pester.Client
	ctx    context.Context
}

func NewHTTPHelp(ctx context.Context, redisClient *redis.Client, client *pester.Client) *HTTPHelp {
	return &HTTPHelp{
		ctx:    ctx,
		redis:  redisClient,
		client: client,
	}
}

func (h *HTTPHelp) FetchURL(needauth bool, url string, r interface{}) error {
	// log.Printf("Fetching %s", url)
	for i := 0; i < 2; i++ {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return err
		}
		req.Header.Add("User-Agent", "pubkraal/go-evepraisal")

		if needauth {
			authToken, err := h.getAccessToken()
			if err != nil {
				log.Printf("Error getting access token: %s", err)
				rerr := h.refreshAuth()
				if rerr != nil {
					return rerr
				} else {
					continue
				}
			}
			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", authToken))
		}
		resp, err := h.client.Do(req.WithContext(h.ctx))
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		switch resp.StatusCode {
		case 200:
			err = json.NewDecoder(resp.Body).Decode(r)
			return err
		case 404:
			return nil
		case 403:
			if needauth {
				err := h.refreshAuth()
				if err != nil {
					return err
				}
			} else {
				return fmt.Errorf("Error talking to esi: %s", resp.Status)
			}
		default:
			return fmt.Errorf("Error talking to esi: %s", resp.Status)
		}
	}
	return fmt.Errorf("Hit end of loop")
}

func (h *HTTPHelp) refreshAuth() error {
	refreshToken, err := h.getRefreshToken()
	if err != nil {
		return err
	}

	requestBody, err := json.Marshal(map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequest(
		"POST",
		"https://login.eveonline.com/oauth/token",
		bytes.NewBuffer(requestBody))
	if err != nil {
		return err
	}

	APIAuth, err := h.APIAuth()
	if err != nil {
		return err
	}

	req.Header.Add("User-Agent", "pubkraal/go-evepraisal")
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", APIAuth))
	req.Header.Add("Content-Type", "application/json")

	resp, err := h.client.Do(req.WithContext(h.ctx))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		// nothing, normal flow continues below.
	case 400:
		return fmt.Errorf("Refresh token rejected. Clearing local data")
	case 401:
		_ = h.redis.Del("evepraisal_apiauth").Err()
		return fmt.Errorf("API auth rejected. Clearing local data")
	default:
		return fmt.Errorf("Error talking to esi: %s", resp.Status)
	}

	newToken := &tokenResponse{}

	err = json.NewDecoder(resp.Body).Decode(newToken)
	if err != nil {
		return err
	}

	// Put new access token in database, with given TTL
	err = h.redis.Set("evepraisal_access", newToken.AccessToken, time.Duration(newToken.ExpiresIn)*time.Second).Err()
	if err != nil {
		return err
	}

	// Put new refresh token in database
	err = h.redis.Set("evepraisal_refresh", newToken.RefreshToken, 0).Err()
	if err != nil {
		return err
	}

	return err
}

func (h *HTTPHelp) APIAuth() (string, error) {
	val, err := h.redis.Get("evepraisal_apiauth").Result()
	if err != nil {
		return "", err
	}
	return val, nil
}

func (h *HTTPHelp) getRefreshToken() (string, error) {
	val, err := h.redis.Get("evepraisal_refresh").Result()
	if err != nil {
		return "", err
	}
	return val, nil
}

func (h *HTTPHelp) getAccessToken() (string, error) {
	val, err := h.redis.Get("evepraisal_access").Result()
	if err != nil {
		return "", err
	}
	return val, nil
}
