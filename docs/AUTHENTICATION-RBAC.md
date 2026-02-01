# Authentication & RBAC Documentation

## Document Information

| Item | Details |
|------|---------|
| Document Version | 1.0 |
| Last Updated | February 2026 |
| Platform | Grafana 12.3.2 |

---

## 1. Overview

This document describes the authentication and Role-Based Access Control (RBAC) configuration for the WAF monitoring platform. Access control is implemented at the Grafana dashboard level with integration options for enterprise authentication providers.

---

## 2. Authentication Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      AUTHENTICATION FLOW                                         │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│   ┌─────────────────┐                                                           │
│   │     User        │                                                           │
│   │   (Browser)     │                                                           │
│   └────────┬────────┘                                                           │
│            │                                                                     │
│            │ HTTPS Request                                                       │
│            ▼                                                                     │
│   ┌─────────────────┐                                                           │
│   │  Nginx WAF      │ ◄── SSL Termination                                       │
│   │  (Reverse Proxy)│ ◄── Request Validation                                    │
│   └────────┬────────┘                                                           │
│            │                                                                     │
│            │ Proxied Request                                                     │
│            ▼                                                                     │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │                           GRAFANA                                        │   │
│   │                                                                          │   │
│   │  ┌──────────────────────────────────────────────────────────────────┐   │   │
│   │  │                  AUTHENTICATION LAYER                             │   │   │
│   │  │                                                                   │   │   │
│   │  │    ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────────┐    │   │   │
│   │  │    │  Local  │   │  LDAP   │   │  OAuth  │   │   SAML 2.0  │    │   │   │
│   │  │    │  Users  │   │  /AD    │   │ (Google │   │   (Okta,    │    │   │   │
│   │  │    │         │   │         │   │  Azure) │   │   Azure AD) │    │   │   │
│   │  │    └─────────┘   └─────────┘   └─────────┘   └─────────────┘    │   │   │
│   │  │                                                                   │   │   │
│   │  └──────────────────────────────────────────────────────────────────┘   │   │
│   │                              │                                           │   │
│   │                              ▼                                           │   │
│   │  ┌──────────────────────────────────────────────────────────────────┐   │   │
│   │  │                  AUTHORIZATION (RBAC)                             │   │   │
│   │  │                                                                   │   │   │
│   │  │    ┌─────────────┐   ┌─────────────┐   ┌─────────────┐          │   │   │
│   │  │    │    Admin    │   │   Editor    │   │   Viewer    │          │   │   │
│   │  │    │    Role     │   │    Role     │   │    Role     │          │   │   │
│   │  │    └─────────────┘   └─────────────┘   └─────────────┘          │   │   │
│   │  │                                                                   │   │   │
│   │  └──────────────────────────────────────────────────────────────────┘   │   │
│   │                                                                          │   │
│   └──────────────────────────────────────────────────────────────────────────┘   │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. User Accounts

### 3.1 Default Accounts

| Account | Username | Password | Role | Purpose |
|---------|----------|----------|------|---------|
| Super Admin | admin | WafAdmin123! | Admin | Full system administration |

### 3.2 Recommended User Structure

| Role | Username Convention | Example | Purpose |
|------|---------------------|---------|---------|
| Admin | admin_[name] | admin_john | System administration |
| Security Analyst | sec_[name] | sec_sarah | Security monitoring |
| Operations | ops_[name] | ops_mike | Operations monitoring |
| Auditor | audit_[name] | audit_lisa | Read-only compliance |

### 3.3 Creating Users

#### Via Grafana UI

1. Login as Admin
2. Navigate to **Administration** → **Users**
3. Click **New user**
4. Fill in details:
   - Name
   - Email
   - Username
   - Password
5. Click **Create user**

#### Via Grafana CLI

```bash
# Create user via CLI
docker exec grafana grafana-cli admin reset-admin-password <new-password>

# Create additional users via API
curl -X POST \
  -H "Content-Type: application/json" \
  -u admin:WafAdmin123! \
  http://localhost:3000/api/admin/users \
  -d '{
    "name": "Security Analyst",
    "email": "security@example.com",
    "login": "sec_analyst",
    "password": "SecurePass123!"
  }'
```

#### Via Environment Variables

```yaml
# docker-compose-monitoring.yml
grafana:
  environment:
    - GF_SECURITY_ADMIN_USER=admin
    - GF_SECURITY_ADMIN_PASSWORD=WafAdmin123!
```

---

## 4. Role-Based Access Control (RBAC)

### 4.1 Built-in Roles

| Role | Dashboard View | Dashboard Edit | Data Sources | Users | Settings |
|------|---------------|----------------|--------------|-------|----------|
| Admin | ✅ All | ✅ All | ✅ Full | ✅ Manage | ✅ All |
| Editor | ✅ All | ✅ Assigned | ❌ View only | ❌ | ❌ |
| Viewer | ✅ Assigned | ❌ | ❌ | ❌ | ❌ |

### 4.2 Role Permissions Detail

#### Admin Role
```
┌─────────────────────────────────────────────────────────────────────────────────┐
│  ADMIN PERMISSIONS                                                               │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ✅ Full dashboard access (create, edit, delete)                                │
│  ✅ Manage data sources (Prometheus, Loki)                                      │
│  ✅ Create and manage organizations                                              │
│  ✅ User management (create, modify, delete)                                    │
│  ✅ Role and permission assignment                                              │
│  ✅ System configuration                                                        │
│  ✅ API key management                                                          │
│  ✅ Alert rule management                                                       │
│  ✅ Annotation creation                                                         │
│  ✅ Explore access                                                              │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

#### Editor Role
```
┌─────────────────────────────────────────────────────────────────────────────────┐
│  EDITOR PERMISSIONS                                                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ✅ View all dashboards                                                         │
│  ✅ Edit dashboards they have access to                                         │
│  ✅ Create new dashboards                                                       │
│  ✅ Create and manage alert rules                                               │
│  ✅ Create annotations                                                          │
│  ✅ Explore access                                                              │
│  ❌ Cannot manage data sources                                                  │
│  ❌ Cannot manage users                                                         │
│  ❌ Cannot access system settings                                               │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

#### Viewer Role
```
┌─────────────────────────────────────────────────────────────────────────────────┐
│  VIEWER PERMISSIONS                                                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ✅ View dashboards they have access to                                         │
│  ✅ View annotations                                                            │
│  ❌ Cannot edit dashboards                                                      │
│  ❌ Cannot create dashboards                                                    │
│  ❌ Cannot manage alerts                                                        │
│  ❌ Cannot use Explore                                                          │
│  ❌ Cannot manage any system features                                           │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 4.3 Assigning Roles

#### To Individual Users

```bash
# Via API - change user role
curl -X PATCH \
  -H "Content-Type: application/json" \
  -u admin:WafAdmin123! \
  http://localhost:3000/api/org/users/2 \
  -d '{"role": "Editor"}'
```

#### To Teams

1. Navigate to **Administration** → **Teams**
2. Create a team (e.g., "Security Team")
3. Add team members
4. Assign team to dashboards with specific permissions

---

## 5. Dashboard Permissions

### 5.1 Permission Levels

| Level | Description |
|-------|-------------|
| View | Can view dashboard |
| Edit | Can edit and save dashboard |
| Admin | Can manage dashboard permissions |

### 5.2 Configuring Dashboard Permissions

#### Via UI

1. Open dashboard
2. Click gear icon (Settings)
3. Go to **Permissions** tab
4. Click **Add a permission**
5. Select User/Team/Role
6. Choose permission level
7. Save

#### Via API

```bash
# Add dashboard permission
curl -X POST \
  -H "Content-Type: application/json" \
  -u admin:WafAdmin123! \
  http://localhost:3000/api/dashboards/uid/waf-security/permissions \
  -d '{
    "items": [
      {"role": "Viewer", "permission": 1},
      {"teamId": 1, "permission": 2},
      {"userId": 5, "permission": 4}
    ]
  }'
```

### 5.3 WAF Dashboard Permission Matrix

| User/Team | WAF Security Dashboard | System Metrics | Explore |
|-----------|------------------------|----------------|---------|
| Admin | Admin | Admin | ✅ |
| Security Team | Edit | View | ✅ |
| Operations Team | View | Edit | ✅ |
| Auditors | View | View | ❌ |
| Executives | View | View | ❌ |

---

## 6. Enterprise Authentication Integration

### 6.1 LDAP/Active Directory

File: `/etc/grafana/ldap.toml`

```toml
[[servers]]
host = "ldap.example.com"
port = 636
use_ssl = true
start_tls = false
ssl_skip_verify = false
bind_dn = "cn=admin,dc=example,dc=com"
bind_password = 'SecureBindPassword'
search_filter = "(sAMAccountName=%s)"
search_base_dns = ["dc=example,dc=com"]

[servers.attributes]
name = "givenName"
surname = "sn"
username = "sAMAccountName"
member_of = "memberOf"
email = "mail"

[[servers.group_mappings]]
group_dn = "cn=Security-Admins,ou=Groups,dc=example,dc=com"
org_role = "Admin"

[[servers.group_mappings]]
group_dn = "cn=Security-Analysts,ou=Groups,dc=example,dc=com"
org_role = "Editor"

[[servers.group_mappings]]
group_dn = "cn=Security-Viewers,ou=Groups,dc=example,dc=com"
org_role = "Viewer"
```

Enable in Grafana:
```yaml
# docker-compose-monitoring.yml
grafana:
  environment:
    - GF_AUTH_LDAP_ENABLED=true
    - GF_AUTH_LDAP_CONFIG_FILE=/etc/grafana/ldap.toml
    - GF_AUTH_LDAP_ALLOW_SIGN_UP=true
```

### 6.2 OAuth2 (Google)

```yaml
# docker-compose-monitoring.yml
grafana:
  environment:
    - GF_AUTH_GOOGLE_ENABLED=true
    - GF_AUTH_GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
    - GF_AUTH_GOOGLE_CLIENT_SECRET=your-client-secret
    - GF_AUTH_GOOGLE_SCOPES=openid email profile
    - GF_AUTH_GOOGLE_AUTH_URL=https://accounts.google.com/o/oauth2/v2/auth
    - GF_AUTH_GOOGLE_TOKEN_URL=https://oauth2.googleapis.com/token
    - GF_AUTH_GOOGLE_ALLOWED_DOMAINS=example.com
    - GF_AUTH_GOOGLE_ALLOW_SIGN_UP=true
```

### 6.3 SAML 2.0 (Okta/Azure AD)

```yaml
# docker-compose-monitoring.yml
grafana:
  environment:
    - GF_AUTH_SAML_ENABLED=true
    - GF_AUTH_SAML_CERTIFICATE_PATH=/etc/grafana/saml/certificate.crt
    - GF_AUTH_SAML_PRIVATE_KEY_PATH=/etc/grafana/saml/private.key
    - GF_AUTH_SAML_IDP_METADATA_URL=https://your-idp.okta.com/app/metadata
    - GF_AUTH_SAML_ASSERTION_ATTRIBUTE_NAME=displayName
    - GF_AUTH_SAML_ASSERTION_ATTRIBUTE_LOGIN=login
    - GF_AUTH_SAML_ASSERTION_ATTRIBUTE_EMAIL=email
    - GF_AUTH_SAML_ASSERTION_ATTRIBUTE_GROUPS=groups
    - GF_AUTH_SAML_ROLE_VALUES_ADMIN=grafana-admins
    - GF_AUTH_SAML_ROLE_VALUES_EDITOR=grafana-editors
```

### 6.4 Azure AD OAuth2

```yaml
# docker-compose-monitoring.yml
grafana:
  environment:
    - GF_AUTH_AZUREAD_ENABLED=true
    - GF_AUTH_AZUREAD_NAME=Azure AD
    - GF_AUTH_AZUREAD_ALLOW_SIGN_UP=true
    - GF_AUTH_AZUREAD_CLIENT_ID=your-azure-client-id
    - GF_AUTH_AZUREAD_CLIENT_SECRET=your-azure-client-secret
    - GF_AUTH_AZUREAD_SCOPES=openid email profile
    - GF_AUTH_AZUREAD_AUTH_URL=https://login.microsoftonline.com/tenant-id/oauth2/v2.0/authorize
    - GF_AUTH_AZUREAD_TOKEN_URL=https://login.microsoftonline.com/tenant-id/oauth2/v2.0/token
    - GF_AUTH_AZUREAD_ALLOWED_DOMAINS=yourdomain.com
```

---

## 7. Security Configuration

### 7.1 Session Security

```yaml
# Grafana security settings
grafana:
  environment:
    # Session configuration
    - GF_SESSION_PROVIDER=file
    - GF_SESSION_PROVIDER_CONFIG=/var/lib/grafana/sessions
    - GF_SESSION_COOKIE_NAME=grafana_session
    - GF_SESSION_COOKIE_SECURE=true
    - GF_SESSION_SESSION_LIFE_TIME=86400
    
    # Security settings
    - GF_SECURITY_COOKIE_SECURE=true
    - GF_SECURITY_COOKIE_SAMESITE=strict
    - GF_SECURITY_STRICT_TRANSPORT_SECURITY=true
    - GF_SECURITY_STRICT_TRANSPORT_SECURITY_MAX_AGE_SECONDS=86400
    - GF_SECURITY_X_CONTENT_TYPE_OPTIONS=true
    - GF_SECURITY_X_XSS_PROTECTION=true
```

### 7.2 Password Policy

```yaml
# Password requirements
grafana:
  environment:
    - GF_SECURITY_ADMIN_PASSWORD=WafAdmin123!
    - GF_USERS_PASSWORD_MIN_LENGTH=12
    # Recommended: Integrate with enterprise IdP for password policy
```

**Recommended Password Requirements:**
- Minimum 12 characters
- Mix of uppercase and lowercase
- At least one number
- At least one special character

### 7.3 API Security

```yaml
# API security settings
grafana:
  environment:
    - GF_AUTH_API_KEY_ENABLED=true
    - GF_AUTH_DISABLE_LOGIN_FORM=false  # Set to true if using SSO only
    - GF_AUTH_DISABLE_SIGNOUT_MENU=false
```

#### Creating API Keys

```bash
# Create admin API key
curl -X POST \
  -H "Content-Type: application/json" \
  -u admin:WafAdmin123! \
  http://localhost:3000/api/auth/keys \
  -d '{
    "name": "automation-key",
    "role": "Admin",
    "secondsToLive": 86400
  }'
```

### 7.4 IP Allowlisting (via Nginx)

```nginx
# In nginx configuration - restrict access to monitoring
server {
    listen 443 ssl http2;
    server_name monitoring.charles.work.gd;
    
    # IP allowlist
    allow 10.0.0.0/8;
    allow 192.168.0.0/16;
    allow 172.16.0.0/12;
    deny all;
    
    location / {
        proxy_pass http://grafana:3000;
        # ... rest of config
    }
}
```

---

## 8. Audit Logging

### 8.1 Enable Audit Logging

```yaml
# docker-compose-monitoring.yml
grafana:
  environment:
    - GF_LOG_MODE=console file
    - GF_LOG_LEVEL=info
    - GF_LOG_FILTERS=auth:debug
```

### 8.2 Audit Events Captured

| Event Category | Events Logged |
|----------------|---------------|
| Authentication | Login, Logout, Failed login attempts |
| Users | Create, Update, Delete, Role changes |
| Dashboards | Create, Update, Delete, Permission changes |
| Data Sources | Create, Update, Delete |
| API Keys | Create, Delete |
| Alerts | Create, Update, Delete, Silence |

### 8.3 Log Format

```json
{
  "t": "2026-02-01T15:30:00Z",
  "level": "info",
  "msg": "User logged in",
  "logger": "context",
  "user": "sec_analyst",
  "userId": 5,
  "uname": "Security Analyst",
  "remote_addr": "192.168.1.100"
}
```

### 8.4 Log Retention

```yaml
# Log rotation via logrotate
/var/lib/grafana/log/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
}
```

---

## 9. Multi-Tenancy (Organizations)

### 9.1 Organization Structure

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    MULTI-TENANT ORGANIZATION STRUCTURE                           │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│                            Grafana Instance                                      │
│                                  │                                               │
│           ┌──────────────────────┼──────────────────────┐                       │
│           │                      │                      │                       │
│           ▼                      ▼                      ▼                       │
│   ┌───────────────┐      ┌───────────────┐      ┌───────────────┐              │
│   │  Org: Main    │      │ Org: Security │      │ Org: DevOps   │              │
│   │               │      │               │      │               │              │
│   │ • Admin users │      │ • SOC Team    │      │ • Ops Team    │              │
│   │ • All access  │      │ • Security    │      │ • System      │              │
│   │               │      │   dashboards  │      │   dashboards  │              │
│   └───────────────┘      └───────────────┘      └───────────────┘              │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 9.2 Creating Organizations

```bash
# Create new organization via API
curl -X POST \
  -H "Content-Type: application/json" \
  -u admin:WafAdmin123! \
  http://localhost:3000/api/orgs \
  -d '{"name": "Security Team"}'
```

### 9.3 Organization Isolation

Each organization has:
- Separate dashboards
- Separate data sources
- Separate user list
- Independent alert rules

---

## 10. Quick Reference

### 10.1 Default Credentials

| Service | Username | Password | URL |
|---------|----------|----------|-----|
| Grafana | admin | WafAdmin123! | https://monitoring.charles.work.gd |

### 10.2 User Management Commands

```bash
# Reset admin password
docker exec grafana grafana-cli admin reset-admin-password NewPassword!

# List users
curl -u admin:WafAdmin123! http://localhost:3000/api/users

# Create user
curl -X POST -H "Content-Type: application/json" \
  -u admin:WafAdmin123! \
  http://localhost:3000/api/admin/users \
  -d '{"name":"User","email":"user@example.com","login":"user","password":"Pass123!"}'

# Delete user
curl -X DELETE -u admin:WafAdmin123! http://localhost:3000/api/admin/users/2
```

### 10.3 Role Assignment Commands

```bash
# Change user role in organization
curl -X PATCH -H "Content-Type: application/json" \
  -u admin:WafAdmin123! \
  http://localhost:3000/api/org/users/2 \
  -d '{"role": "Viewer"}'
```

### 10.4 Security Checklist

- [ ] Change default admin password
- [ ] Enable HTTPS for Grafana
- [ ] Configure session timeouts
- [ ] Set up audit logging
- [ ] Implement IP allowlisting
- [ ] Use enterprise SSO (LDAP/SAML/OAuth)
- [ ] Create role-appropriate user accounts
- [ ] Configure dashboard permissions
- [ ] Review audit logs regularly
- [ ] Rotate API keys periodically

---

**Document End**
