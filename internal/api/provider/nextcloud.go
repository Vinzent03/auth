package provider

import (
	"context"
	"strconv"
	"strings"

	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
)

// Gitlab

type nextcloudProvider struct {
	*oauth2.Config
	Host string
}


type nextcloudUser struct {
	Email       string `json:"email"`
	Name        string `json:"name"`
	AvatarURL   string `json:"avatar_url"`
	ConfirmedAt string `json:"confirmed_at"`
	ID          int    `json:"id"`
}

type nextcloudUserEmail struct {
	ID    int    `json:"id"`
	Email string `json:"email"`
}

// NewNextcloudProvider creates a Nextcloud account provider.
func NewNextcloudProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	oauthScopes := []string{}

	host := chooseHost(ext.URL, "")
	return &nextcloudProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  host + "/oauth/authorize",
				TokenURL: host + "/oauth/token",
			},
			RedirectURL: ext.RedirectURI,
			Scopes:      oauthScopes,
		},
		Host: host,
	}, nil
}

func (g nextcloudProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return g.Exchange(context.Background(), code)
}

func (g nextcloudProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u nextcloudUser

	if err := makeRequest(ctx, tok, g.Config, g.Host+"/api/v4/user", &u); err != nil {
		return nil, err
	}

	data := &UserProvidedData{}

	var emails []*nextcloudUserEmail
	if err := makeRequest(ctx, tok, g.Config, g.Host+"/api/v4/user/emails", &emails); err != nil {
		return nil, err
	}

	for _, e := range emails {
		// additional emails from GitLab don't return confirm status
		if e.Email != "" {
			data.Emails = append(data.Emails, Email{Email: e.Email, Verified: false, Primary: false})
		}
	}

	if u.Email != "" {
		verified := u.ConfirmedAt != ""
		data.Emails = append(data.Emails, Email{Email: u.Email, Verified: verified, Primary: true})
	}

	data.Metadata = &Claims{
		Issuer:  g.Host,
		Subject: strconv.Itoa(u.ID),
		Name:    u.Name,
		Picture: u.AvatarURL,

		// To be deprecated
		AvatarURL:  u.AvatarURL,
		FullName:   u.Name,
		ProviderId: strconv.Itoa(u.ID),
	}

	return data, nil
}
