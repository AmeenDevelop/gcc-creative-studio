gcp_project_id = "YOUR_GCP_PROJECT_ID"
gcp_region     = "us-central1"
environment    = "development"

# --- Service Names ---
backend_service_name  = "cstudio-backend-dev"
frontend_service_name = "cstudio-frontend-dev" # This is the Cloud Run service name
firebase_site_id      = "YOUR_FIREBASE_SITE_ID" # (Optional) Custom Firebase Hosting Site ID, defaults to the gcp_project_id

# --- GitHub Repo Details ---
github_conn_name   = "gh-repo-owner-con"
github_repo_owner  = "RepoOwnerName"
github_repo_name   = "repo-owner-gcc-creative-studio"
github_branch_name = "develop"

# --- Custom Audiences ---
backend_custom_audiences  = ["YOUR_OAUTH_WEB_CLIENT_ID_HERE", "YOUR_GCP_PROJECT_ID"]
frontend_custom_audiences = ["YOUR_OAUTH_WEB_CLIENT_ID_HERE", "YOUR_GCP_PROJECT_ID"]

# --- Service-Specific Environment Variables ---
be_env_vars = {
  common = {
    LOG_LEVEL = "INFO"
  }
  development = {
    ENVIRONMENT  = "development"
    GOOGLE_TOKEN_AUDIENCE = "YOUR_OAUTH_WEB_CLIENT_ID_HERE"
    IDENTITY_PLATFORM_ALLOWED_ORGS = "" # If empty then any org is allowed
    # --- Microsoft Entra ID (optional) ---
    # Leave the three ENTRA_* vars empty to disable Microsoft sign-in.
    # When set, the backend will accept Microsoft-signed ID tokens and
    # (if ENTRA_ALLOWED_GROUP_IDS is non-empty) enforce membership in
    # at least one of the listed Entra security groups.
    ENTRA_TENANT_ID          = ""          # Directory (tenant) ID GUID from Entra
    ENTRA_CLIENT_ID          = ""          # Application (client) ID of the Entra App Registration
    ENTRA_ALLOWED_GROUP_IDS  = ""          # Comma-separated Entra group Object IDs
  }
  production = {
    ENVIRONMENT  = "production"
    GOOGLE_TOKEN_AUDIENCE = "YOUR_OAUTH_WEB_CLIENT_ID_HERE"
    IDENTITY_PLATFORM_ALLOWED_ORGS = "" # If empty then any org is allowed
    ENTRA_TENANT_ID          = ""
    ENTRA_CLIENT_ID          = ""
    ENTRA_ALLOWED_GROUP_IDS  = ""
  }
}

fe_build_substitutions = {
  _ANGULAR_BUILD_COMMAND = "build-dev"
  # GCIP / Identity Platform OIDC provider ID for Microsoft Entra (e.g.
  # "oidc.microsoft"). Leave empty to hide the "Login with Microsoft"
  # button. The value must match the Provider ID you configured in the
  # GCP console under "Identity Platform" → "Providers" → your OIDC
  # provider.
  _MICROSOFT_OIDC_PROVIDER_ID = ""
}

# Top-level variable consumed by the platform module; mirrors the
# substitution above so the frontend build receives it.
microsoft_oidc_provider_id = ""

frontend_secrets = [
  "FIREBASE_API_KEY",          # Your Firebase Web API Key
  "FIREBASE_AUTH_DOMAIN",      # Your Firebase Auth Domain (e.g., project-id.firebaseapp.com)
  "FIREBASE_PROJECT_ID",       # Your Firebase Project ID
  "FIREBASE_STORAGE_BUCKET",   # Your Firebase Storage Bucket (e.g., project-id.appspot.com)
  "FIREBASE_MESSAGING_SENDER_ID", # Your Firebase Cloud Messaging Sender ID
  "FIREBASE_APP_ID",           # Your Firebase Web App ID
  "FIREBASE_MEASUREMENT_ID",   # Your Google Analytics Measurement ID
  "GOOGLE_CLIENT_ID",          # Your Google OAuth 2.0 Client ID for web
]

backend_secrets = [
  "GOOGLE_TOKEN_AUDIENCE",
]

backend_runtime_secrets = {
  "GOOGLE_TOKEN_AUDIENCE" = "GOOGLE_TOKEN_AUDIENCE"
}

apis_to_enable = [
  "serviceusage.googleapis.com",     # Required to enable other APIs
  "iam.googleapis.com",              # Required for IAM management
  "cloudbuild.googleapis.com",       # Required for Cloud Build
  "artifactregistry.googleapis.com", # Required for Artifact Registry
  "run.googleapis.com",              # Required for Cloud Run
  "cloudresourcemanager.googleapis.com",
  "compute.googleapis.com",
  "cloudfunctions.googleapis.com",
  "iamcredentials.googleapis.com",
  "aiplatform.googleapis.com",
  "firestore.googleapis.com",
  "texttospeech.googleapis.com",
  "workflows.googleapis.com",
]
