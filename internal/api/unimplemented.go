// Code generated from gen.StrictServerInterface; DELETE once every handler exists.

package api

import (
	"context"
	"net/http"

	"github.com/x6c-co/rypt-store/internal/api/gen"
)

// unimplemented answers 501 for operations not built yet.
type unimplemented struct{}

func (unimplemented) StartDeviceAuth(context.Context, gen.StartDeviceAuthRequestObject) (gen.StartDeviceAuthResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "StartDeviceAuth is not implemented")
}

func (unimplemented) ApproveDeviceAuth(context.Context, gen.ApproveDeviceAuthRequestObject) (gen.ApproveDeviceAuthResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "ApproveDeviceAuth is not implemented")
}

func (unimplemented) GetDeviceAuth(context.Context, gen.GetDeviceAuthRequestObject) (gen.GetDeviceAuthResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "GetDeviceAuth is not implemented")
}

func (unimplemented) PollDeviceToken(context.Context, gen.PollDeviceTokenRequestObject) (gen.PollDeviceTokenResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "PollDeviceToken is not implemented")
}

func (unimplemented) GetInvitation(context.Context, gen.GetInvitationRequestObject) (gen.GetInvitationResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "GetInvitation is not implemented")
}

func (unimplemented) AcceptInvitation(context.Context, gen.AcceptInvitationRequestObject) (gen.AcceptInvitationResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "AcceptInvitation is not implemented")
}

func (unimplemented) Login(context.Context, gen.LoginRequestObject) (gen.LoginResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "Login is not implemented")
}

func (unimplemented) Logout(context.Context, gen.LogoutRequestObject) (gen.LogoutResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "Logout is not implemented")
}

func (unimplemented) VerifyRecoveryCode(context.Context, gen.VerifyRecoveryCodeRequestObject) (gen.VerifyRecoveryCodeResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "VerifyRecoveryCode is not implemented")
}

func (unimplemented) VerifyTotp(context.Context, gen.VerifyTotpRequestObject) (gen.VerifyTotpResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "VerifyTotp is not implemented")
}

func (unimplemented) BeginWebauthnLogin(context.Context, gen.BeginWebauthnLoginRequestObject) (gen.BeginWebauthnLoginResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "BeginWebauthnLogin is not implemented")
}

func (unimplemented) FinishWebauthnLogin(context.Context, gen.FinishWebauthnLoginRequestObject) (gen.FinishWebauthnLoginResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "FinishWebauthnLogin is not implemented")
}

func (unimplemented) ResetPassword(context.Context, gen.ResetPasswordRequestObject) (gen.ResetPasswordResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "ResetPassword is not implemented")
}

func (unimplemented) ListInstanceAudit(context.Context, gen.ListInstanceAuditRequestObject) (gen.ListInstanceAuditResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "ListInstanceAudit is not implemented")
}

func (unimplemented) ExportInstanceAudit(context.Context, gen.ExportInstanceAuditRequestObject) (gen.ExportInstanceAuditResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "ExportInstanceAudit is not implemented")
}

func (unimplemented) VerifyInstanceAudit(context.Context, gen.VerifyInstanceAuditRequestObject) (gen.VerifyInstanceAuditResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "VerifyInstanceAudit is not implemented")
}

func (unimplemented) GetInstanceKeys(context.Context, gen.GetInstanceKeysRequestObject) (gen.GetInstanceKeysResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "GetInstanceKeys is not implemented")
}

func (unimplemented) ListKeyMigrations(context.Context, gen.ListKeyMigrationsRequestObject) (gen.ListKeyMigrationsResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "ListKeyMigrations is not implemented")
}

func (unimplemented) StartKeyMigration(context.Context, gen.StartKeyMigrationRequestObject) (gen.StartKeyMigrationResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "StartKeyMigration is not implemented")
}

func (unimplemented) GetKeyMigration(context.Context, gen.GetKeyMigrationRequestObject) (gen.GetKeyMigrationResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "GetKeyMigration is not implemented")
}

func (unimplemented) GetInstanceSettings(context.Context, gen.GetInstanceSettingsRequestObject) (gen.GetInstanceSettingsResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "GetInstanceSettings is not implemented")
}

func (unimplemented) ListInstanceUsers(context.Context, gen.ListInstanceUsersRequestObject) (gen.ListInstanceUsersResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "ListInstanceUsers is not implemented")
}

func (unimplemented) CreateUserPasswordReset(context.Context, gen.CreateUserPasswordResetRequestObject) (gen.CreateUserPasswordResetResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "CreateUserPasswordReset is not implemented")
}

func (unimplemented) GetMe(context.Context, gen.GetMeRequestObject) (gen.GetMeResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "GetMe is not implemented")
}

func (unimplemented) RegenerateRecoveryCodes(context.Context, gen.RegenerateRecoveryCodesRequestObject) (gen.RegenerateRecoveryCodesResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "RegenerateRecoveryCodes is not implemented")
}

func (unimplemented) RemoveTotp(context.Context, gen.RemoveTotpRequestObject) (gen.RemoveTotpResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "RemoveTotp is not implemented")
}

func (unimplemented) BeginTotpEnrollment(context.Context, gen.BeginTotpEnrollmentRequestObject) (gen.BeginTotpEnrollmentResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "BeginTotpEnrollment is not implemented")
}

func (unimplemented) ConfirmTotpEnrollment(context.Context, gen.ConfirmTotpEnrollmentRequestObject) (gen.ConfirmTotpEnrollmentResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "ConfirmTotpEnrollment is not implemented")
}

func (unimplemented) ListPasskeys(context.Context, gen.ListPasskeysRequestObject) (gen.ListPasskeysResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "ListPasskeys is not implemented")
}

func (unimplemented) BeginPasskeyRegistration(context.Context, gen.BeginPasskeyRegistrationRequestObject) (gen.BeginPasskeyRegistrationResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "BeginPasskeyRegistration is not implemented")
}

func (unimplemented) FinishPasskeyRegistration(context.Context, gen.FinishPasskeyRegistrationRequestObject) (gen.FinishPasskeyRegistrationResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "FinishPasskeyRegistration is not implemented")
}

func (unimplemented) RemovePasskey(context.Context, gen.RemovePasskeyRequestObject) (gen.RemovePasskeyResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "RemovePasskey is not implemented")
}

func (unimplemented) ChangePassword(context.Context, gen.ChangePasswordRequestObject) (gen.ChangePasswordResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "ChangePassword is not implemented")
}

func (unimplemented) ListMySessions(context.Context, gen.ListMySessionsRequestObject) (gen.ListMySessionsResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "ListMySessions is not implemented")
}

func (unimplemented) RevokeMySession(context.Context, gen.RevokeMySessionRequestObject) (gen.RevokeMySessionResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "RevokeMySession is not implemented")
}

func (unimplemented) CompleteSetup(context.Context, gen.CompleteSetupRequestObject) (gen.CompleteSetupResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "CompleteSetup is not implemented")
}

func (unimplemented) GetSetupStatus(context.Context, gen.GetSetupStatusRequestObject) (gen.GetSetupStatusResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "GetSetupStatus is not implemented")
}

func (unimplemented) BeginSetupTotp(context.Context, gen.BeginSetupTotpRequestObject) (gen.BeginSetupTotpResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "BeginSetupTotp is not implemented")
}

func (unimplemented) ListTenants(context.Context, gen.ListTenantsRequestObject) (gen.ListTenantsResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "ListTenants is not implemented")
}

func (unimplemented) CreateTenant(context.Context, gen.CreateTenantRequestObject) (gen.CreateTenantResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "CreateTenant is not implemented")
}

func (unimplemented) GetTenant(context.Context, gen.GetTenantRequestObject) (gen.GetTenantResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "GetTenant is not implemented")
}

func (unimplemented) ListTenantAudit(context.Context, gen.ListTenantAuditRequestObject) (gen.ListTenantAuditResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "ListTenantAudit is not implemented")
}

func (unimplemented) ExportTenantAudit(context.Context, gen.ExportTenantAuditRequestObject) (gen.ExportTenantAuditResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "ExportTenantAudit is not implemented")
}

func (unimplemented) VerifyTenantAudit(context.Context, gen.VerifyTenantAuditRequestObject) (gen.VerifyTenantAuditResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "VerifyTenantAudit is not implemented")
}

func (unimplemented) ListInvitations(context.Context, gen.ListInvitationsRequestObject) (gen.ListInvitationsResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "ListInvitations is not implemented")
}

func (unimplemented) CreateInvitation(context.Context, gen.CreateInvitationRequestObject) (gen.CreateInvitationResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "CreateInvitation is not implemented")
}

func (unimplemented) ListMembers(context.Context, gen.ListMembersRequestObject) (gen.ListMembersResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "ListMembers is not implemented")
}

func (unimplemented) RemoveMember(context.Context, gen.RemoveMemberRequestObject) (gen.RemoveMemberResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "RemoveMember is not implemented")
}

func (unimplemented) UpdateMember(context.Context, gen.UpdateMemberRequestObject) (gen.UpdateMemberResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "UpdateMember is not implemented")
}

func (unimplemented) CreateMemberPasswordReset(context.Context, gen.CreateMemberPasswordResetRequestObject) (gen.CreateMemberPasswordResetResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "CreateMemberPasswordReset is not implemented")
}

func (unimplemented) ListProjects(context.Context, gen.ListProjectsRequestObject) (gen.ListProjectsResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "ListProjects is not implemented")
}

func (unimplemented) CreateProject(context.Context, gen.CreateProjectRequestObject) (gen.CreateProjectResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "CreateProject is not implemented")
}

func (unimplemented) DeleteProject(context.Context, gen.DeleteProjectRequestObject) (gen.DeleteProjectResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "DeleteProject is not implemented")
}

func (unimplemented) GetProject(context.Context, gen.GetProjectRequestObject) (gen.GetProjectResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "GetProject is not implemented")
}

func (unimplemented) UpdateProject(context.Context, gen.UpdateProjectRequestObject) (gen.UpdateProjectResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "UpdateProject is not implemented")
}

func (unimplemented) CompareSecrets(context.Context, gen.CompareSecretsRequestObject) (gen.CompareSecretsResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "CompareSecrets is not implemented")
}

func (unimplemented) ListEnvironments(context.Context, gen.ListEnvironmentsRequestObject) (gen.ListEnvironmentsResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "ListEnvironments is not implemented")
}

func (unimplemented) CreateEnvironment(context.Context, gen.CreateEnvironmentRequestObject) (gen.CreateEnvironmentResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "CreateEnvironment is not implemented")
}

func (unimplemented) DeleteEnvironment(context.Context, gen.DeleteEnvironmentRequestObject) (gen.DeleteEnvironmentResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "DeleteEnvironment is not implemented")
}

func (unimplemented) UpdateEnvironment(context.Context, gen.UpdateEnvironmentRequestObject) (gen.UpdateEnvironmentResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "UpdateEnvironment is not implemented")
}

func (unimplemented) ListSecrets(context.Context, gen.ListSecretsRequestObject) (gen.ListSecretsResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "ListSecrets is not implemented")
}

func (unimplemented) CreateSecret(context.Context, gen.CreateSecretRequestObject) (gen.CreateSecretResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "CreateSecret is not implemented")
}

func (unimplemented) ListDeletedSecrets(context.Context, gen.ListDeletedSecretsRequestObject) (gen.ListDeletedSecretsResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "ListDeletedSecrets is not implemented")
}

func (unimplemented) RestoreDeletedSecret(context.Context, gen.RestoreDeletedSecretRequestObject) (gen.RestoreDeletedSecretResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "RestoreDeletedSecret is not implemented")
}

func (unimplemented) ExportSecrets(context.Context, gen.ExportSecretsRequestObject) (gen.ExportSecretsResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "ExportSecrets is not implemented")
}

func (unimplemented) ImportSecrets(context.Context, gen.ImportSecretsRequestObject) (gen.ImportSecretsResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "ImportSecrets is not implemented")
}

func (unimplemented) GetSecretValues(context.Context, gen.GetSecretValuesRequestObject) (gen.GetSecretValuesResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "GetSecretValues is not implemented")
}

func (unimplemented) DeleteSecret(context.Context, gen.DeleteSecretRequestObject) (gen.DeleteSecretResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "DeleteSecret is not implemented")
}

func (unimplemented) GetSecret(context.Context, gen.GetSecretRequestObject) (gen.GetSecretResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "GetSecret is not implemented")
}

func (unimplemented) UpdateSecret(context.Context, gen.UpdateSecretRequestObject) (gen.UpdateSecretResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "UpdateSecret is not implemented")
}

func (unimplemented) ListSecretVersions(context.Context, gen.ListSecretVersionsRequestObject) (gen.ListSecretVersionsResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "ListSecretVersions is not implemented")
}

func (unimplemented) GetSecretVersion(context.Context, gen.GetSecretVersionRequestObject) (gen.GetSecretVersionResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "GetSecretVersion is not implemented")
}

func (unimplemented) RestoreSecretVersion(context.Context, gen.RestoreSecretVersionRequestObject) (gen.RestoreSecretVersionResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "RestoreSecretVersion is not implemented")
}

func (unimplemented) ChangeProjectKeyMode(context.Context, gen.ChangeProjectKeyModeRequestObject) (gen.ChangeProjectKeyModeResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "ChangeProjectKeyMode is not implemented")
}

func (unimplemented) ListServiceTokens(context.Context, gen.ListServiceTokensRequestObject) (gen.ListServiceTokensResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "ListServiceTokens is not implemented")
}

func (unimplemented) CreateServiceToken(context.Context, gen.CreateServiceTokenRequestObject) (gen.CreateServiceTokenResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "CreateServiceToken is not implemented")
}

func (unimplemented) RevokeServiceToken(context.Context, gen.RevokeServiceTokenRequestObject) (gen.RevokeServiceTokenResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "RevokeServiceToken is not implemented")
}

func (unimplemented) GetHealthz(context.Context, gen.GetHealthzRequestObject) (gen.GetHealthzResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "GetHealthz is not implemented")
}

func (unimplemented) GetReadyz(context.Context, gen.GetReadyzRequestObject) (gen.GetReadyzResponseObject, error) {
	return nil, problem(http.StatusNotImplemented, "not_implemented", "GetReadyz is not implemented")
}
