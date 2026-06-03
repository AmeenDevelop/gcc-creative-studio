/**
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import {Injectable, PLATFORM_ID, inject} from '@angular/core';
import {Router} from '@angular/router';
import {UserModel, UserRolesEnum} from '../models/user.model';
import {HttpClient, HttpHeaders, HttpErrorResponse} from '@angular/common/http';
import {environment} from '../../../environments/environment';
import {Auth, IdTokenResult} from '@angular/fire/auth';
import {UserService} from '../services/user.service';
import {
  GoogleAuthProvider,
  OAuthProvider,
  signInWithPopup,
  UserCredential,
} from '@angular/fire/auth';
import {Observable, from, throwError, of} from 'rxjs';
import {catchError, tap, map, switchMap} from 'rxjs/operators';
import {isPlatformBrowser} from '@angular/common';

// Declare the 'google' global object from the Google Identity Services script
declare const google: any;

const FIREBASE_SESSION_KEY = 'firebase_session';
const USER_DETAILS = 'USER_DETAILS';
const LOGIN_ROUTE = '/login';

type LoginProvider = 'google' | 'microsoft';

interface FirebaseSession {
  token: string;
  expiry: number; // Expiration timestamp in milliseconds
  // Which provider produced this token. When 'microsoft', `token` is the
  // raw Microsoft Entra ID token (NOT a Firebase token) so the backend
  // can verify the `groups` claim. Older sessions (without this field)
  // are treated as 'google' for backwards compatibility.
  provider?: LoginProvider;
}

@Injectable({
  providedIn: 'root',
})
export class AuthService {
  private readonly auth: Auth = inject(Auth);
  private platformId = inject(PLATFORM_ID);
  private readonly provider: GoogleAuthProvider = new GoogleAuthProvider();

  // Store token temporarily in memory for the session
  private currentOAuthAccessToken: string | null = null;
  private firebaseIdToken: string | null = null; // To store the Firebase token for the test
  private firebaseTokenExpiry: number | null = null; // To store token expiration time (in ms)
  // Which provider the active session was issued by. Used to decide
  // whether to send the Firebase token or the raw Microsoft Entra ID
  // token as the bearer to the backend.
  private loginProvider: LoginProvider = 'google';

  constructor(
    private router: Router,
    private httpClient: HttpClient,
    private userService: UserService,
  ) {
    this.provider.setCustomParameters({
      // Set custom params for the provider
      prompt: 'select_account',
    });
    this.loadSessionFromStorage();
  }

  /**
   * Sign in with Microsoft Entra ID via the Identity Platform OIDC
   * provider (e.g. 'oidc.microsoft'). After Firebase's popup completes,
   * we capture the ORIGINAL Microsoft ID token (not the Firebase token)
   * via OAuthProvider.credentialFromResult, because the backend needs
   * the Microsoft-signed token to verify the security-group claim.
   */
  signInWithMicrosoft(): Observable<string> {
    const providerId = environment.MICROSOFT_OIDC_PROVIDER_ID;
    if (!providerId) {
      return throwError(
        () =>
          new Error(
            'Microsoft sign-in is not configured. ' +
              'Set MICROSOFT_OIDC_PROVIDER_ID in the environment.',
          ),
      );
    }

    const msProvider = new OAuthProvider(providerId);
    msProvider.setCustomParameters({prompt: 'select_account'});
    // Ask Entra for `openid`/`profile`/`email` so the ID token carries
    // standard identity claims. The `groups` claim is configured on the
    // App Registration side, not via scopes.
    msProvider.addScope('openid');
    msProvider.addScope('profile');
    msProvider.addScope('email');

    return from(signInWithPopup(this.auth, msProvider)).pipe(
      switchMap((userCredential: UserCredential) => {
        if (!userCredential.user) {
          return throwError(
            () =>
              new Error('Firebase user not found after Microsoft sign-in.'),
          );
        }
        const credential = OAuthProvider.credentialFromResult(userCredential);
        const msIdToken = credential?.idToken;
        if (!msIdToken) {
          return throwError(
            () =>
              new Error(
                'Microsoft ID token not returned by sign-in. ' +
                  'Verify the GCIP OIDC provider is configured to return ' +
                  'the ID token.',
              ),
          );
        }

        // Parse expiry from the Microsoft ID token (`exp` is seconds
        // since epoch). Microsoft tokens last ~1 hour by default.
        const payload = JSON.parse(atob(msIdToken.split('.')[1]));
        const expiry = (payload.exp as number) * 1000;

        this.loginProvider = 'microsoft';
        this.firebaseIdToken = msIdToken;
        this.firebaseTokenExpiry = expiry;
        const session: FirebaseSession = {
          token: msIdToken,
          expiry,
          provider: 'microsoft',
        };
        localStorage.setItem(FIREBASE_SESSION_KEY, JSON.stringify(session));

        return this.syncUserWithBackend$(msIdToken).pipe(map(() => msIdToken));
      }),
      catchError((error: any) => {
        console.error('Microsoft sign-in failed:', error);
        return throwError(
          () => new Error(`Microsoft sign-in failed. ${error?.message ?? error}`),
        );
      }),
    );
  }

  /**
   * A test sign-in method to get a Google ID token compatible with Firebase.
   *
   * @returns An Observable that emits the Firebase-compatible ID token.
   */
  signInWithGoogleFirebase(): Observable<string> {
    return from(signInWithPopup(this.auth, this.provider)).pipe(
      // Step 1: Get the Firebase ID token from the successful sign-in.
      switchMap((userCredential: UserCredential) => {
        if (!userCredential.user) {
          return throwError(
            () => new Error('Firebase user not found after sign-in.'),
          );
        }
        return from(userCredential.user.getIdTokenResult());
      }),
      // Step 2: Save the session and sync with the backend.
      switchMap((idTokenResult: IdTokenResult) => {
        const token = idTokenResult.token;
        const expirationTime = Date.parse(idTokenResult.expirationTime);

        // Save session details to memory and local storage.
        this.loginProvider = 'google';
        this.firebaseIdToken = token;
        this.firebaseTokenExpiry = expirationTime;
        const session: FirebaseSession = {
          token,
          expiry: expirationTime,
          provider: 'google',
        };
        localStorage.setItem(FIREBASE_SESSION_KEY, JSON.stringify(session));

        // Call the backend to get or create the user profile.
        return this.syncUserWithBackend$(token).pipe(
          map(() => token), // Pass the token along for the final result.
        );
      }),
      catchError((error: any) => {
        console.error('An error occurred during the sign-in process:', error);
        return throwError(
          () => new Error(`Sign-in failed. Please try again. ${error}`),
        );
      }),
    );
  }

  /**
   * Asynchronously gets a valid Firebase token.
   * 1. Checks for a valid, non-expired token in memory/cache.
   * 2. If expired or missing, attempts a silent refresh.
   * 3. If silent refresh fails, it emits an error, signaling a required re-login.
   */
  getValidFirebaseToken$(): Observable<string> {
    // First, check our own session info which is loaded from localStorage.
    // This is synchronous and tells us if we have a valid, non-expired token.
    if (!this.isLoggedIn()) {
      return throwError(
        () => new Error('User session is not valid or has expired. 1'),
      );
    }

    // Microsoft sessions: we hold the raw Entra ID token which the
    // Firebase SDK cannot refresh on its own. Return the stored token
    // and let the isLoggedIn() guard force a re-login when it expires.
    if (this.loginProvider === 'microsoft') {
      return of(this.firebaseIdToken!);
    }

    // If we have a valid session, check if the Firebase Auth instance is ready.
    const currentUser = this.auth.currentUser;
    if (currentUser) {
      // Ideal case: Auth is ready, so we can force a token refresh to ensure it's fresh.
      return from(currentUser.getIdToken(true)).pipe(
        tap((token: string) => {
          // Update the in-memory cache and localStorage with the refreshed token info.
          const payload = JSON.parse(atob(token.split('.')[1]));
          const expiry = payload.exp * 1000;

          this.firebaseIdToken = token;
          this.firebaseTokenExpiry = expiry;

          const session: FirebaseSession = {
            token,
            expiry,
            provider: 'google',
          };
          localStorage.setItem(FIREBASE_SESSION_KEY, JSON.stringify(session));
        }),
      );
    }

    // Fallback case: The Firebase Auth instance is not yet initialized, but we
    // have a valid token from localStorage. We can use this for the current
    // request. The next request will likely hit the ideal case above.
    return of(this.firebaseIdToken!);
  }

  /**
   * A test sign-in method to get a Google ID token compatible with Identity Platform.
   *
   * @returns An Observable that emits the Identity Platform-compatible ID token.
   */
  signInForGoogleIdentityPlatform(): Observable<string> {
    return this.promptForIdentityPlatformToken$().pipe(
      switchMap(idToken => {
        const payload = JSON.parse(atob(idToken.split('.')[1]));
        const userEmail = payload.email?.toLowerCase();

        // If allowed, proceed to save session and return token
        this.loginProvider = 'google';
        this.firebaseIdToken = idToken;
        this.firebaseTokenExpiry = payload.exp * 1000;

        const session: FirebaseSession = {
          token: idToken,
          expiry: this.firebaseTokenExpiry,
          provider: 'google',
        };
        localStorage.setItem(FIREBASE_SESSION_KEY, JSON.stringify(session));

        // Call the backend to get or create the user profile.
        return this.syncUserWithBackend$(idToken).pipe(
          map(() => idToken), // Pass the token along for the final result.
        );
      }),
    );
  }

  private promptForIdentityPlatformToken$(): Observable<string> {
    const GOOGLE_CLIENT_ID = environment.GOOGLE_CLIENT_ID;

    return new Observable<string>(observer => {
      if (typeof google === 'undefined') {
        return observer.error(
          new Error(
            'Google Identity Services script not loaded. Add it to index.html',
          ),
        );
      }

      const loginTimeout = setTimeout(() => {
        observer.error(
          new Error(
            'Login timed out or third party sign-in may be disabled. Please try again and enable third party sign-in by clicking on the information button at the top left side of the browser.',
          ),
        );
      }, 15000);

      try {
        google.accounts.id.initialize({
          client_id: GOOGLE_CLIENT_ID,
          callback: (response: any) => {
            clearTimeout(loginTimeout);
            const idToken = response.credential;
            if (idToken) {
              observer.next(idToken);
              observer.complete();
            } else {
              observer.error(
                new Error(
                  'Google Sign-In response did not contain a credential.',
                ),
              );
            }
          },
        });

        // Trigger the One Tap prompt.
        // Per new docs, we don't use the notification object for flow control.
        google.accounts.id.prompt();
      } catch (error) {
        clearTimeout(loginTimeout);
        console.error(
          'Error during Google Identity Platform sign-in initialization:',
          error,
        );
        observer.error(error);
      }
    });
  }

  /**
   * Asynchronously gets a valid Identity Platform token.
   * 1. Checks for a valid, non-expired token in memory/cache.
   * 2. If expired or missing, attempts a silent refresh.
   * 3. If silent refresh fails, it emits an error, signaling a required re-login.
   */
  getValidIdentityPlatformToken$(): Observable<string> {
    // First, check our own session info which is loaded from localStorage.
    // This is synchronous and tells us if we have a valid, non-expired token.
    if (!this.isLoggedIn()) {
      return of();
    }

    // Fallback case: The Firebase Auth instance is not yet initialized, but we
    // have a valid token from localStorage. We can use this for the current
    // request. The next request will likely hit the ideal case above.
    return of(this.firebaseIdToken!);
  }

  private syncUserWithBackend$(token: string): Observable<UserModel> {
    const headers = new HttpHeaders().set('Authorization', `Bearer ${token}`);
    return this.httpClient
      .get<UserModel>(`${environment.backendURL}/users/me`, {headers})
      .pipe(
        tap((userDetails: UserModel) => {
          // The backend is the source of truth. Save the returned profile to local storage.
          localStorage.setItem(USER_DETAILS, JSON.stringify(userDetails));
          console.log('User profile successfully synced with backend.');
        }),
        catchError((error: HttpErrorResponse) => {
          console.error('Failed to sync user with backend', error);
          // This is a critical error, so we should propagate it.
          return throwError(
            () =>
              new Error(
                error?.error?.detail ||
                  `Could not synchronize user profile with the server. ${error?.error?.detail}`,
              ),
          );
        }),
      );
  }

  async logout(route: string = LOGIN_ROUTE) {
    return this.auth
      .signOut()
      .then(() => {
        this.currentOAuthAccessToken = null; // Clear stored token on logout
        // Clear Firebase session data
        this.firebaseIdToken = null;
        this.firebaseTokenExpiry = null;
        this.loginProvider = 'google';
        localStorage.removeItem(FIREBASE_SESSION_KEY);
        localStorage.removeItem(USER_DETAILS);
        localStorage.removeItem('showTooltip');
        void this.router.navigateByUrl(route);
      })
      .catch(e => {
        console.error('Sign Out Error', e);
        localStorage.removeItem(FIREBASE_SESSION_KEY);
        localStorage.removeItem(USER_DETAILS);
        localStorage.removeItem('showTooltip');
        void this.router.navigate([LOGIN_ROUTE]);
      });
  }

  isLoggedIn() {
    if (!isPlatformBrowser(this.platformId)) return false;

    // Check if the in-memory token is valid
    const now = Date.now();
    const isTokenValid = !!(
      this.firebaseIdToken &&
      this.firebaseTokenExpiry &&
      this.firebaseTokenExpiry > now
    );

    if (!isTokenValid && this.router.url !== LOGIN_ROUTE) {
      void this.router.navigate([LOGIN_ROUTE]);
    }

    return isTokenValid;
  }

  private loadSessionFromStorage(): void {
    if (!isPlatformBrowser(this.platformId)) return;

    const sessionStr = localStorage.getItem(FIREBASE_SESSION_KEY);
    if (sessionStr) {
      const session: FirebaseSession = JSON.parse(sessionStr);
      // Check if the stored session is still valid
      if (session.expiry > Date.now()) {
        this.firebaseIdToken = session.token;
        this.firebaseTokenExpiry = session.expiry;
        this.loginProvider = session.provider ?? 'google';
      } else {
        // If expired, remove it from storage.
        localStorage.removeItem(FIREBASE_SESSION_KEY);
      }
    }
  }

  isUserLoggedIn() {
    if (!isPlatformBrowser(this.platformId)) return false;

    const isUserLoggedIn = localStorage.getItem(FIREBASE_SESSION_KEY) !== null;
    return isUserLoggedIn;
  }

  isUserAdmin() {
    if (!isPlatformBrowser(this.platformId)) return false;

    const user_role = this.userService.getUserDetails()?.roles;
    return user_role?.includes(UserRolesEnum.ADMIN) || false;
  }

  isUserWorkflows() {
    if (!isPlatformBrowser(this.platformId)) return false;

    const user_role = this.userService.getUserDetails()?.roles;
    return user_role?.includes(UserRolesEnum.WORKFLOWS) || false;
  }

  getToken() {
    return this.firebaseIdToken;
  }

  setOAuthAccessToken(token: string | null): void {
    this.currentOAuthAccessToken = token;
  }

  getOAuthAccessToken(): string | null {
    // Renamed from getAccessToken for clarity
    return this.currentOAuthAccessToken;
  }

  /**
   * Retrieves the currently stored access token.
   */
  getAccessToken(): string | null {
    // Note: Tokens expire (usually after 1 hour).
    // A robust implementation would check expiry or refresh the token.
    // Firebase Auth automatically handles ID token refresh, but OAuth access token
    // refresh requires re-authentication or more complex flows not covered here.
    // For a simple deploy button click, getting a fresh token on sign-in might suffice.
    return this.currentOAuthAccessToken;
  }
}
