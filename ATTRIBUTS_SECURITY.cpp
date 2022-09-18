// ATTRIBUTS_SECURITY.cpp : Définit les fonctions de la bibliothèque statique.
//

#include "pch.h"
#include "framework.h"

// TODO: Il s'agit d'un exemple de fonction de bibliothèque
void fnATTRIBUTSSECURITY()
{
}
// plein acces pour tous les Utilisateurs
// a ne pas mettre par defaut
#include <Windows.h>
#include "ATTRIBUTS_SECURITY.h"
SECURITY_ATTRIBUTES  sa;
SECURITY_DESCRIPTOR  sd;

SECURITY_ATTRIBUTES SecuriteDesactiveePourTousW() {
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
    SetSecurityDescriptorGroup(&sd, NULL, FALSE);
    SetSecurityDescriptorSacl(&sd, FALSE, NULL, FALSE);
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = TRUE;
    return sa;
}
SECURITY_ATTRIBUTES SecuriteDesactiveePourTousA() {
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
    SetSecurityDescriptorGroup(&sd, NULL, FALSE);
    SetSecurityDescriptorSacl(&sd, FALSE, NULL, FALSE);
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = TRUE;
    return sa;
}
DWORD CreerDossierHackSecuriteAttributsW(LPCWSTR DestinationDir) {
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
    SetSecurityDescriptorGroup(&sd, NULL, FALSE);
    SetSecurityDescriptorSacl(&sd, FALSE, NULL, FALSE);
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = TRUE;
    return CreateDirectoryW(DestinationDir, &sa);
}
DWORD CreerDossierHackSecuriteAttributsA(LPCSTR DestinationDir) {
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
    SetSecurityDescriptorGroup(&sd, NULL, FALSE);
    SetSecurityDescriptorSacl(&sd, FALSE, NULL, FALSE);
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = TRUE;
    return CreateDirectoryA(DestinationDir, &sa);
}
DWORD CreerDossierAvecSecuriteW(LPCTSTR lpPath) {
    PACL                 pAcl = NULL;
    DWORD                cbAcl = 0, dwNeeded = 0, dwError = 0;
    HANDLE               hToken;
    PTOKEN_USER          ptu = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))  return GetLastError();
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwNeeded);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) { dwError = GetLastError(); goto cleanup; }
    ptu = (TOKEN_USER*)malloc(dwNeeded);
    if (!GetTokenInformation(hToken, TokenUser, ptu, dwNeeded, &dwNeeded)) { dwError = GetLastError();  goto cleanup; }
    cbAcl = sizeof(ACL) + ((sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD)) + GetLengthSid(ptu->User.Sid));
    pAcl = (ACL*)malloc(cbAcl);
    if (!InitializeAcl(pAcl, cbAcl, ACL_REVISION)) { dwError = GetLastError(); goto cleanup; }
    if (!AddAccessAllowedAce(pAcl, ACL_REVISION, GENERIC_ALL | STANDARD_RIGHTS_ALL | SPECIFIC_RIGHTS_ALL, ptu->User.Sid)) { dwError = GetLastError(); goto cleanup; }
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, pAcl, FALSE);
    SetSecurityDescriptorOwner(&sd, ptu->User.Sid, FALSE);
    SetSecurityDescriptorGroup(&sd, NULL, FALSE);
    SetSecurityDescriptorSacl(&sd, FALSE, NULL, FALSE);
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = TRUE;
    CreateDirectory(lpPath, &sa);
    dwError = GetLastError();
cleanup:
    if (ptu) free(ptu);
    if (pAcl) free(pAcl);
    CloseHandle(hToken);
    return dwError;
}
DWORD CreerDossierAvecSecuriteA(LPCWSTR lpPath) {
    PACL                 pAcl = NULL;
    DWORD                cbAcl = 0, dwNeeded = 0, dwError = 0;
    HANDLE               hToken;
    PTOKEN_USER          ptu = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))  return GetLastError();
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwNeeded);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) { dwError = GetLastError(); goto cleanup; }
    ptu = (TOKEN_USER*)malloc(dwNeeded);
    if (!GetTokenInformation(hToken, TokenUser, ptu, dwNeeded, &dwNeeded)) { dwError = GetLastError();  goto cleanup; }
    cbAcl = sizeof(ACL) + ((sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD)) + GetLengthSid(ptu->User.Sid));
    pAcl = (ACL*)malloc(cbAcl);
    if (!InitializeAcl(pAcl, cbAcl, ACL_REVISION)) { dwError = GetLastError(); goto cleanup; }
    if (!AddAccessAllowedAce(pAcl, ACL_REVISION, GENERIC_ALL | STANDARD_RIGHTS_ALL | SPECIFIC_RIGHTS_ALL, ptu->User.Sid)) { dwError = GetLastError(); goto cleanup; }
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, pAcl, FALSE);
    SetSecurityDescriptorOwner(&sd, ptu->User.Sid, FALSE);
    SetSecurityDescriptorGroup(&sd, NULL, FALSE);
    SetSecurityDescriptorSacl(&sd, FALSE, NULL, FALSE);
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = TRUE;
    CreateDirectory(lpPath, &sa);
    dwError = GetLastError();
cleanup:
    if (ptu) free(ptu);
    if (pAcl) free(pAcl);
    CloseHandle(hToken);
    return dwError;
}
