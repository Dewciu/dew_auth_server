package outputs

type IClientRegisterOutput interface {
	GetClientID() string
	GetClientSecret() string
}

type ClientRegisterOutput struct {
	ClientID     string
	ClientSecret string
}

func (o *ClientRegisterOutput) GetClientID() string {
	return o.ClientID
}

func (o *ClientRegisterOutput) GetClientSecret() string {
	return o.ClientSecret
}
