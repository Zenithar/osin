package rethinkdb

import (
	"github.com/RangelReale/osin"
	"time"
)

type (
	/*
	 * OAuthClient represents data known for client identification
	 */
	OAuthClient struct {
		// Client Identifier
		ID string `gorethink:"id,omitempty"`

		// Client Secret
		Secret string `gorethink:"secret"`

		// Redirection URL after login
		RedirectURI string `gorethink:"redirectUri"`
	}

	/*
	 * OAuthAuthorizeData represents data used to create an authorization token.
	 */
	OAuthAuthorizeData struct {
		// Client information
		ClientID string `gorethink:"client_id"`

		// Authorization code
		Code string `gorethink:"code"`

		// Token expiration in seconds
		ExpiresIn int32 `gorethink:"expiresIn"`

		// Requested scope
		Scope string `gorethink:"scope"`

		// Redirect Uri from request
		RedirectUri string `gorethink:"redirectUri"`

		// State data from request
		State string `gorethink:"state"`

		// Date created
		CreatedAt time.Time `gorethink:"createdAt"`
	}

	/*
	 * OAuthAccessToken represents data claimed by the access token
	 */
	OAuthAccessData struct {
		// Client information
		ClientID string `gorethink:"client_id"`

		// Authorization
		AuthorizationCode *string `gorethink:"authorizationCode"`

		// Access token
		AccessToken string `gorethink:"accessToken"`

		// Refresh Token. Can be blank
		RefreshToken string `gorethink:"refreshToken"`

		// Token expiration in seconds
		ExpiresIn int32 `gorethink:"expiresIn"`

		// Requested scope
		Scope string `gorethink:"scope"`

		// Redirect Uri from request
		RedirectUri string `gorethink:"redirectUri"`

		// Date created
		CreatedAt time.Time `gorethink:"createdAt"`
	}
)

func (cl *OAuthClient) ToClient() *osin.Client {
	var client = osin.Client{
		Id:          cl.ID,
		RedirectUri: cl.RedirectURI,
		Secret:      cl.Secret,
		UserData:    cl,
	}
	return &client
}

func FromClient(client *osin.Client) *OAuthClient {
	var cl = OAuthClient{
		ID:          client.Id,
		RedirectURI: client.RedirectUri,
		Secret:      client.Secret,
	}
	return &cl
}

func (a *OAuthAuthorizeData) ToAuthorizeData() *osin.AuthorizeData {
	return &osin.AuthorizeData{
		Code:        a.Code,
		ExpiresIn:   a.ExpiresIn,
		Scope:       a.Scope,
		RedirectUri: a.RedirectUri,
		State:       a.State,
		CreatedAt:   a.CreatedAt,
	}
}

func FromAuthorizeData(auth *osin.AuthorizeData) *OAuthAuthorizeData {
	return &OAuthAuthorizeData{
		ClientID:    auth.Client.Id,
		Code:        auth.Code,
		ExpiresIn:   auth.ExpiresIn,
		Scope:       auth.Scope,
		RedirectUri: auth.RedirectUri,
		State:       auth.State,
		CreatedAt:   auth.CreatedAt,
	}
}

func (at *OAuthAccessData) ToAccessData() *osin.AccessData {
	return &osin.AccessData{
		AccessToken:  at.AccessToken,
		RefreshToken: at.RefreshToken,
		ExpiresIn:    at.ExpiresIn,
		Scope:        at.Scope,
		RedirectUri:  at.RedirectUri,
		CreatedAt:    at.CreatedAt,
		UserData:     at,
	}
}

func FromAccessData(data *osin.AccessData) *OAuthAccessData {

	var oad = OAuthAccessData{
		AccessToken:  data.AccessToken,
		RefreshToken: data.RefreshToken,
		ExpiresIn:    data.ExpiresIn,
		Scope:        data.Scope,
		RedirectUri:  data.RedirectUri,
		CreatedAt:    data.CreatedAt,
	}
	if data.AuthorizeData == nil {
		// Client Credentials
		oad.AuthorizationCode = nil
	}
	return &oad
}
