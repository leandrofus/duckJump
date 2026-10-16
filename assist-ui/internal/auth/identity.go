package auth

import (
	"os"
	"os/user"
	"runtime"
	"strings"
)

// AccountType distinguishes between local, Active Directory, or SSO accounts.
type AccountType string

const (
	AccountLocal AccountType = "local"
	AccountAD    AccountType = "ad"
	AccountSSO   AccountType = "sso"
)

// UserIdentity holds workstation and user identity information.
type UserIdentity struct {
	Username       string
	Domain         string
	DisplayName    string
	Hostname       string
	OS             string
	AccountType    AccountType
	IsDomainJoined bool
}

// DetectIdentity automatically identifies the current workstation user and domain context.
func DetectIdentity() UserIdentity {
	hostname, _ := os.Hostname()
	osName := runtime.GOOS

	id := UserIdentity{
		Hostname:    hostname,
		OS:          osName,
		AccountType: AccountLocal,
	}

	u, err := user.Current()
	if err == nil && u != nil {
		id.Username = u.Username
		id.DisplayName = u.Name
		if id.DisplayName == "" {
			id.DisplayName = u.Username
		}
	} else {
		id.Username = os.Getenv("USERNAME")
		if id.Username == "" {
			id.Username = os.Getenv("USER")
		}
		id.DisplayName = id.Username
	}

	switch runtime.GOOS {
	case "windows":
		userDomain := os.Getenv("USERDOMAIN")
		compName := os.Getenv("COMPUTERNAME")
		dnsDomain := os.Getenv("USERDNSDOMAIN") // e.g., CORP.ACME.COM

		if userDomain != "" && compName != "" && !strings.EqualFold(userDomain, compName) {
			id.AccountType = AccountAD
			id.IsDomainJoined = true
			id.Domain = userDomain
			if dnsDomain != "" {
				id.Domain = dnsDomain
			}
		} else {
			id.AccountType = AccountLocal
			id.Domain = compName
		}

	default:
		// On Linux / macOS, check for Active Directory integration (SSSD, Winbind, Kerberos)
		if strings.Contains(id.Username, "\\") {
			parts := strings.SplitN(id.Username, "\\", 2)
			id.Domain = parts[0]
			id.Username = parts[1]
			id.AccountType = AccountAD
			id.IsDomainJoined = true
		} else if strings.Contains(id.Username, "@") {
			parts := strings.SplitN(id.Username, "@", 2)
			id.Username = parts[0]
			id.Domain = parts[1]
			id.AccountType = AccountAD
			id.IsDomainJoined = true
		} else if os.Getenv("KRB5CCNAME") != "" {
			id.AccountType = AccountAD
			id.IsDomainJoined = true
		}
	}

	return id
}

// FullTargetName formats the username for display or submission (e.g. DOMAIN\user).
func (u UserIdentity) FullTargetName() string {
	if u.Domain != "" && u.AccountType == AccountAD {
		return u.Domain + "\\" + u.Username
	}
	return u.Username
}
