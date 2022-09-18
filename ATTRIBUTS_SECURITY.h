#pragma once
//ATTRIBUTS_SECURITY.H

SECURITY_ATTRIBUTES SecuriteDesactiveePourTousW();
SECURITY_ATTRIBUTES SecuriteDesactiveePourTousA();
DWORD CreerDossierHackSecuriteAttributsW(LPCWSTR DestinationDir);
DWORD CreerDossierHackSecuriteAttributsA(LPCSTR DestinationDir);
DWORD CreerDossierAvecSecuriteW(LPCTSTR lpPath);
DWORD CreerDossierAvecSecuriteA(LPCWSTR lpPath);

#ifdef UNICODE
#define CreerDossierHackSecuriteAttributs CreerDossierHackSecuriteAttributsW
#define SecuriteDesactiveePourTous SecuriteDesactiveePourTousW
#define CreerDossierAvecSecurite CreerDossierAvecSecuriteW

#else
#define CreateDirectory  CreateDirectoryA
#define CreerDossierHackSecuriteAttributs CreerDossierHackSecuriteAttributsA
#define CreerDossierAvecSecurite CreerDossierAvecSecuriteA
#define SecuriteDesactiveePourTous SecuriteDesactiveePourTousA
#endif // !UNICODE
