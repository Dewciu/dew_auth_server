package inputs

var _ IClientRegisterInput = new(ClientRegisterInput)

type IClientRegisterInput interface {
	GetClientName() string
	GetClientEmail() string
	GetRedirectURI() string
	GetResponseTypes() string
	GetGrantTypes() string
	GetScopes() string
}

type ClientRegisterInput struct {
	ClientName    string `form:"client_name" binding:"required"`
	ClientEmail   string `form:"client_email" binding:"required,email"`
	RedirectURI   string `form:"redirect_uri" binding:"required"`
	ResponseTypes string `form:"response_types" binding:"required"`
	GrantTypes    string `form:"grant_types" binding:"required"`
	Scopes        string `form:"scopes" binding:"required"`
}

func (i ClientRegisterInput) GetClientName() string {
	return i.ClientName
}

func (i ClientRegisterInput) GetClientEmail() string {
	return i.ClientEmail
}

func (i ClientRegisterInput) GetRedirectURI() string {
	return i.RedirectURI
}

func (i ClientRegisterInput) GetResponseTypes() string {
	return i.ResponseTypes
}

func (i ClientRegisterInput) GetGrantTypes() string {
	return i.GrantTypes
}

func (i ClientRegisterInput) GetScopes() string {
	return i.Scopes
}
