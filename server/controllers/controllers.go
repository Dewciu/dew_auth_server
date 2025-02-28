package controllers

type Controllers struct {
	AccessTokenController    AccessTokenController
	AuthorizationController  AuthorizationController
	ClientRegisterController ClientRegisterController
	UserRegisterController   UserRegisterController
	UserLoginController      UserLoginController
	IndexController          IndexController
	ConsentController        ConsentController
	IntrospectionController  IntrospectionController
	RevocationController     RevocationController
}
