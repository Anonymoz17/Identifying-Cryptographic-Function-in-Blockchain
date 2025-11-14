# Sequence Diagram: User Login with Google (Free User)

## User Story
As a free user, I want to login using my Google account so that I can access the blockchain cryptographic analysis tool without creating a separate password.

## Sequence Diagram

```mermaid
sequenceDiagram
    actor User
    participant LoginUI as Login Page<br/>(login.py)
    participant CallbackServer as Local Callback Server<br/>(127.0.0.1:8750)
    participant Browser
    participant Supabase as Supabase Auth Service
    participant Google as Google OAuth Provider
    participant DB as Database<br/>(user_roles table)
    participant AppState as Application State<br/>(app.py)
    participant Landing as Landing Page<br/>(landing.py)

    %% Step 1-3: Initiate Login
    User->>LoginUI: Click "Continue with Google"
    activate LoginUI
    LoginUI->>LoginUI: _do_google_signin()
    LoginUI->>LoginUI: Set busy state
    LoginUI->>CallbackServer: Start HTTP server
    activate CallbackServer
    CallbackServer-->>LoginUI: Server ready on :8750

    %% Step 4-5: Generate OAuth URL
    LoginUI->>Supabase: sign_in_with_oauth({<br/>provider: "google",<br/>redirect_to: "http://127.0.0.1:8750/auth/callback"<br/>})
    activate Supabase
    Supabase-->>LoginUI: OAuth authorization URL
    deactivate Supabase

    %% Step 6-7: Open Browser
    LoginUI->>Browser: Open OAuth URL
    activate Browser
    Browser->>Google: Request authorization
    activate Google
    Google-->>Browser: Display consent screen
    deactivate Google

    %% Step 8-9: User Authentication
    User->>Browser: Grant permissions
    Browser->>Google: User consent
    activate Google
    Google->>Google: Validate credentials
    Google-->>Browser: Redirect with auth code
    deactivate Google
    Browser->>CallbackServer: GET /auth/callback?code=xxx

    %% Step 10-11: Capture Authorization Code
    CallbackServer->>CallbackServer: Extract auth code
    CallbackServer-->>Browser: Success message
    deactivate Browser
    CallbackServer->>LoginUI: Return auth code
    deactivate CallbackServer

    %% Step 12-13: Exchange Code for Session
    LoginUI->>Supabase: exchange_code_for_session({<br/>auth_code: code<br/>})
    activate Supabase
    Supabase->>Google: Validate auth code
    activate Google
    Google-->>Supabase: User info + tokens
    deactivate Google
    Supabase-->>LoginUI: Session data {<br/>access_token: JWT,<br/>user: {id, email}<br/>}
    deactivate Supabase

    %% Step 14-15: Finalize Login
    LoginUI->>LoginUI: _finish_login(token, user)
    LoginUI->>Supabase: ensure_role_row(token, user_id)
    activate Supabase

    %% Step 16-17: Create/Verify Role
    Supabase->>DB: SELECT * FROM user_roles<br/>WHERE id = user_id
    activate DB
    alt Role exists
        DB-->>Supabase: Role record
    else Role doesn't exist
        DB-->>Supabase: No record
        Supabase->>DB: INSERT INTO user_roles<br/>(id, tier)<br/>VALUES (user_id, 'free')
        DB-->>Supabase: Success
    end
    deactivate DB
    Supabase-->>LoginUI: Role ensured
    deactivate Supabase

    %% Step 18-19: Fetch User Role
    LoginUI->>Supabase: get_my_role(token, user_id)
    activate Supabase
    Supabase->>DB: SELECT tier FROM user_roles<br/>WHERE id = user_id
    activate DB
    DB-->>Supabase: tier = "free"
    deactivate DB
    Supabase-->>LoginUI: role = "free"
    deactivate Supabase

    %% Step 20-21: Update Application State
    LoginUI->>AppState: Set session state:<br/>- auth_token = JWT<br/>- current_user = {id, email}<br/>- current_user_role = "free"
    activate AppState
    AppState-->>LoginUI: State updated
    deactivate AppState

    %% Step 22-23: Navigate to Landing
    LoginUI->>Landing: switch_page("landing")
    deactivate LoginUI
    activate Landing
    Landing-->>User: Display landing page<br/>(Free tier features visible)
    deactivate Landing
```

## Key Components

### 1. **Login Page (login.py)**
- Provides UI with Google OAuth button
- Manages OAuth flow initiation
- Handles login completion and state management

### 2. **Local Callback Server**
- Runs on `127.0.0.1:8750` during OAuth flow
- Captures authorization code from redirect
- Listens on `/auth/callback` endpoint
- Automatically stops after code capture

### 3. **Supabase Auth Service**
- Generates OAuth authorization URLs
- Exchanges authorization codes for session tokens
- Manages user authentication state
- Provides JWT tokens for API authorization

### 4. **Google OAuth Provider**
- Displays consent screen
- Validates user credentials
- Issues authorization codes
- Provides user identity information

### 5. **Database (user_roles table)**
- Stores user tier information (free/premium/admin)
- Default tier: "free"
- Links to Supabase auth.users via foreign key

### 6. **Application State (app.py)**
- Stores session data in memory:
  - `auth_token`: JWT for API calls
  - `current_user`: User object {id, email}
  - `current_user_role`: Tier level ("free")
- Manages page navigation
- Persists for application lifetime

## Free User Characteristics

After successful login, free users have:

1. **Database Record**:
   - Entry in `user_roles` table with `tier = "free"`
   - Entry in `auth.users` table (managed by Supabase)

2. **Session State**:
   - Valid JWT token (short-lived, typically 1 hour)
   - Role set to "free"
   - Access to basic features

3. **Feature Access**:
   - Limited scan capabilities
   - Basic analysis features
   - Cannot export results (premium feature)
   - No scan history (premium feature)

4. **Upgrade Path**:
   - Can upgrade to premium via payment
   - Admin can manually upgrade tier
   - Upgrade changes `user_roles.tier` to "premium"

## Security Notes

1. **OAuth Flow**: Uses Authorization Code flow (secure for native apps)
2. **Local Callback**: Only accepts requests on localhost
3. **Token Security**: JWT tokens never stored in files or version control
4. **Authorization Code**: Single-use, short-lived code
5. **Row-Level Security**: Supabase RLS policies protect user data
6. **No Client Secrets**: All secrets managed server-side by Supabase

## Error Handling

The flow includes error handling for:
- Timeout waiting for OAuth callback (180 seconds)
- Failed code exchange
- Database connection errors
- Missing role records (auto-created)
- Token validation failures

## Alternative Flows

This diagram shows the desktop application flow. The web application has a similar flow but:
- No local callback server (uses Supabase's built-in redirect handling)
- Session persisted in browser localStorage
- Automatic token refresh enabled
- Same database schema and role system
