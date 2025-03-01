package controllers

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/dewciu/dew_auth_server/server/appcontext"
	"github.com/dewciu/dew_auth_server/server/controllers/inputs"
	"github.com/dewciu/dew_auth_server/server/controllers/oautherrors"
	"github.com/dewciu/dew_auth_server/server/services"
	"github.com/dewciu/dew_auth_server/server/services/serviceerrors"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/ing-bank/ginerr/v2"
	"github.com/sirupsen/logrus"
)

type AuthorizationController struct {
	authorizationService services.IAuthorizationService
	consentService       services.IConsentService
	clientService        services.IClientService
	consentEndpoint      string
}

func NewAuthorizationController(
	authorizationService services.IAuthorizationService,
	consentService services.IConsentService,
	clientService services.IClientService,
	consentEndpoint string,
) AuthorizationController {
	return AuthorizationController{
		authorizationService: authorizationService,
		consentService:       consentService,
		clientService:        clientService,
		consentEndpoint:      consentEndpoint,
	}
}

func (ac *AuthorizationController) Authorize(c *gin.Context) {
	ctx := c.Request.Context()

	authInput := inputs.AuthorizationInput{}
	if err := c.ShouldBindQuery(&authInput); err != nil {
		e := oautherrors.NewOAuthInputValidationError(err, authInput)
		c.JSON(ginerr.NewErrorResponse(ctx, e))
		return
	}

	session := sessions.Default(c)
	userID := appcontext.MustGetUserID(ctx)

	client, err := ac.clientService.CheckIfClientExistsByID(
		c.Request.Context(),
		authInput.GetClientID(),
	)

	if err != nil {
		ac.redirectWithError(c, authInput.GetRedirectURI(),
			oautherrors.ErrServerError,
			"client does not exist")
		return
	}

	session.Set("client_id", authInput.GetClientID())
	if err := session.Save(); err != nil {
		logrus.WithError(err).Error("failed to save session")
		ac.redirectWithError(c, authInput.GetRedirectURI(),
			oautherrors.ErrServerError,
			"failed to process authorization request")
		return
	}

	consentExists, err := ac.consentService.ConsentForClientAndUserExists(
		ctx,
		client.ID.String(),
		userID,
	)

	if err != nil {
		logrus.WithError(err).Error("error checking consent status")
		ac.redirectWithError(c, authInput.GetRedirectURI(),
			oautherrors.ErrServerError,
			"failed to verify consent status")
		return
	}

	if !consentExists {
		session.Set("auth_redirect_uri", c.Request.RequestURI)
		session.Set("client_redirect_uri", authInput.GetRedirectURI())
		if err := session.Save(); err != nil {
			logrus.WithError(err).Error("failed to save session before consent redirect")
			ac.redirectWithError(c, authInput.GetRedirectURI(),
				oautherrors.ErrServerError,
				"failed to process consent request")
			return
		}

		logrus.WithFields(logrus.Fields{
			"endpoint":  ac.consentEndpoint,
			"client_id": client.ID.String(),
			"user_id":   userID,
		}).Debug("redirecting to consent page")

		c.Redirect(http.StatusFound, ac.consentEndpoint)
		return
	}

	output, err := ac.authorizationService.AuthorizeClient(ctx, authInput)

	if err != nil {
		var errorType oautherrors.OAuthErrorType
		var errorDescription string

		switch e := err.(type) {
		case serviceerrors.InvalidRedirectURIError, serviceerrors.InvalidRedirectURIForClientError, serviceerrors.UnsupportedPKCEMethodError:
			errorType = oautherrors.ErrInvalidRequest
			errorDescription = e.Error()
		case serviceerrors.UnsupportedResponseTypeError:
			errorType = oautherrors.ErrUnsupportedResponseType
			errorDescription = e.Error()
		case serviceerrors.InvalidScopeError:
			errorType = oautherrors.ErrInvalidScope
			errorDescription = e.Error()
		case serviceerrors.ClientNotFoundError:
			errorType = oautherrors.ErrInvalidClient
			errorDescription = e.Error()
		case serviceerrors.CodeGenerationError:
			errorType = oautherrors.ErrServerError
			errorDescription = "Failed to generate authorization code"
		case serviceerrors.InvalidClientSecretError:
			errorType = oautherrors.ErrInvalidClient
			errorDescription = "Invalid client credentials"
		default:
			errorType = oautherrors.ErrServerError
			errorDescription = "An error occurred while processing the request"
			logrus.WithError(err).Error("Unhandled error during authorization")
		}

		ac.redirectWithError(c, authInput.GetRedirectURI(), errorType, errorDescription)
		return
	}

	params := fmt.Sprintf("?code=%s&state=%s", output.GetCode(), output.GetState())
	c.Redirect(
		http.StatusFound,
		authInput.RedirectURI+params,
	)
}

func (ac *AuthorizationController) redirectWithError(c *gin.Context, redirectURI string, errorType oautherrors.OAuthErrorType, errorDescription string) {
	redirectURI = fmt.Sprintf("%s?error=%s&error_description=%s",
		redirectURI,
		url.QueryEscape(string(errorType)),
		url.QueryEscape(errorDescription))

	logrus.WithFields(logrus.Fields{
		"redirect_uri":      redirectURI,
		"error_type":        errorType,
		"error_description": errorDescription,
	}).Debug("redirecting with error")

	c.Redirect(
		http.StatusFound,
		redirectURI,
	)
}
