package outputs

var _ IAuthorizeOutput = new(AuthorizeOutput)

type IAuthorizeOutput interface {
	GetCode() string
	GetState() string
}

type AuthorizeOutput struct {
	Code  string `json:"code" name:"code" binding:"required"`
	State string `json:"state" name:"state" binding:"required"`
}

func (i AuthorizeOutput) GetCode() string {
	return i.Code
}

func (i AuthorizeOutput) GetState() string {
	return i.State
}
