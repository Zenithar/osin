package rethinkdb

import (
	"errors"
	"fmt"
	"github.com/RangelReale/osin"
	r "github.com/dancannon/gorethink"
	"log"
	"time"
)

const (
	oauthClientTable    string = "oauth_client"
	oauthAuthorityTable string = "oauth_authorization"
	oauthAccessTable    string = "oauth_access_token"
)

type RethinkdbStorage struct {
	Address  string
	Database string
	session  *r.Session
}

func NewRethinkdbStorage(address string, database string) *RethinkdbStorage {
	session, err := r.Connect(r.ConnectOpts{
		Address:     address,
		Database:    database,
		MaxIdle:     10,
		IdleTimeout: time.Second * 10,
	})

	if err != nil {
		log.Fatalln(err.Error())
	}
	s := &RethinkdbStorage{
		Address:  address,
		Database: database,
		session:  session,
	}
	return s
}

func (s *RethinkdbStorage) GetClient(id string) (*osin.Client, error) {
	fmt.Printf("GetClient: %s\n", id)

	var client = new(OAuthClient)
	row, err := r.Table(oauthClientTable).Get(id).Run(s.session)
	if err != nil {
		return nil, err
	}
	if row.IsNil() {
		return nil, errors.New("Client not found")
	}
	err = row.One(client)
	return client.ToClient(), err
}

func (s *RethinkdbStorage) SetClient(id string, client *osin.Client) error {
	fmt.Printf("SetClient: %s\n", id)

	var cl = FromClient(client)
	_, err := r.Table(oauthClientTable).Update(cl).Run(s.session)
	if err != nil {
		return err
	}
	return nil
}

func (s *RethinkdbStorage) SaveAuthorize(data *osin.AuthorizeData) error {
	fmt.Printf("SaveAuthorize: %s\n", data.Code)

	var auth = FromAuthorizeData(data)
	_, err := r.Table(oauthAuthorityTable).Insert(auth).RunWrite(s.session)

	if err != nil {
		return err
	}
	return nil
}

func (s *RethinkdbStorage) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	fmt.Printf("LoadAuthorize: %s\n", code)
	var auth = new(OAuthAuthorizeData)
	row, err := r.Table(oauthAuthorityTable).GetAllByIndex("code", code).Run(s.session)
	if err != nil {
		return nil, err
	}
	if row.IsNil() {
		return nil, errors.New("Authorization not found")
	}
	err = row.One(auth)
	if err != nil {
		return nil, err
	}

	var rauth = auth.ToAuthorizeData()
	client, err := s.GetClient(auth.ClientID)
	if client == nil || err != nil {
		return nil, errors.New("AccessToken invalid : client not found !")
	}
	rauth.Client = client

	fmt.Printf("%+v\n", rauth)
	return rauth, err

}

func (s *RethinkdbStorage) RemoveAuthorize(code string) error {
	fmt.Printf("RemoveAuthorize: %s\n", code)
	_, err := r.Table(oauthAuthorityTable).GetAllByIndex("code", code).Delete().Run(s.session)
	if err != nil {
		return err
	}
	return nil
}

func (s *RethinkdbStorage) SaveAccess(data *osin.AccessData) error {
	fmt.Printf("SaveAccess: %s\n", data.AccessToken)

	client, err := s.GetClient(data.Client.Id)
	if client == nil || err != nil {
		return errors.New("AccessToken invalid : client not found !")
	}

	if data.AuthorizeData != nil {
		auth, err := s.LoadAuthorize(data.AuthorizeData.Code)
		if auth == nil || err != nil {
			return errors.New("AccessToken invalid : authorization not found !")
		}
	}

	var token = FromAccessData(data)
	token.ClientID = client.Id

	_, err = r.Table(oauthAccessTable).Insert(token).RunWrite(s.session)
	return err
}

func (s *RethinkdbStorage) LoadAccess(code string) (*osin.AccessData, error) {
	fmt.Printf("LoadAccess: %s\n", code)
	var token = new(OAuthAccessData)
	row, err := r.Table(oauthAccessTable).GetAllByIndex("accessToken", code).Run(s.session)
	if err != nil {
		return nil, err
	}
	if row.IsNil() {
		return nil, errors.New("AccessToken not found")
	}
	err = row.One(token)
	if err != nil {
		return nil, err
	}

	var rtoken = token.ToAccessData()

	client, err := s.GetClient(token.ClientID)
	if client == nil || err != nil {
		return nil, errors.New("AccessToken invalid : client not found !")
	}
	rtoken.Client = client

	if token.AuthorizationCode != nil {
		auth, err := s.LoadAuthorize(*token.AuthorizationCode)
		if auth == nil || err != nil {
			return nil, errors.New("AccessToken invalid : authorization not found !")
		}
		rtoken.AuthorizeData = auth
	}

	return rtoken, nil
}

func (s *RethinkdbStorage) RemoveAccess(code string) error {
	fmt.Printf("RemoveAccess: %s\n", code)
	_, err := r.Table(oauthAccessTable).GetAllByIndex("accessToken", code).Delete().Run(s.session)
	if err != nil {
		return err
	}
	return nil
}

func (s *RethinkdbStorage) LoadRefresh(code string) (*osin.AccessData, error) {
	fmt.Printf("LoadRefresh: %s\n", code)
	var token = new(OAuthAccessData)
	row, err := r.Table(oauthAccessTable).GetAllByIndex("refreshToken", code).Run(s.session)
	if err != nil {
		return nil, err
	}
	if row.IsNil() {
		return nil, errors.New("RefreshToken not found")
	}
	err = row.One(token)
	if err != nil {
		return nil, err
	}
	return s.LoadAccess(token.AccessToken)
}

func (s *RethinkdbStorage) RemoveRefresh(code string) error {
	fmt.Printf("RemoveRefresh: %s\n", code)
	_, err := r.Table(oauthAccessTable).GetAllByIndex("refreshToken", code).Delete().Run(s.session)
	if err != nil {
		return err
	}
	return nil
}
