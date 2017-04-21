package com.microsoft.aad.adal;

import android.webkit.CookieManager;

import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

class AcquireTokenSilentWithCookieHandler {
    private static final String TAG = AcquireTokenSilentWithCookieHandler.class.getSimpleName();
    private static final String LOCATION_HEADER_KEY = "Location";

    private final AuthenticationRequest mAuthRequest;

    private IWebRequestHandler mWebRequestHandler = null;

    AcquireTokenSilentWithCookieHandler(final AuthenticationRequest authRequest) {
        if (authRequest == null) {
            throw new IllegalArgumentException("authRequest");
        }

        mAuthRequest = authRequest;

        mWebRequestHandler = new WebRequestHandler();
    }

    AuthenticationResult acquireToken()
            throws AuthenticationException {
        Oauth2 oauth = new Oauth2(mAuthRequest);
        String url;

        try {
            url = oauth.getCodeRequestUrl();

            HttpWebResponse response = mWebRequestHandler.sendGet(new URL(url), getCookieHeader(url));
            String authorizationUrl = getAuthorizationUrl(response);

            HashMap<String, String> parameters = StringExtensions.getUrlParameters(authorizationUrl);

            return Oauth2.processUIResponseParams(parameters);
        } catch (Exception e) {
            AuthenticationException exc = new AuthenticationException(ADALError.AUTH_FAILED_INTERNAL_ERROR, e.getMessage());
            Logger.e(TAG, "Error in refresh token for request:" + mAuthRequest.getLogInfo(),
                    ExceptionExtensions.getExceptionMessage(e), ADALError.AUTH_FAILED_INTERNAL_ERROR,
                    exc);

            throw exc;
        }
    }

    private Map<String, String> getCookieHeader(String url) {
        Map<String, String> headers = new HashMap<>();

        CookieManager manager = CookieManager.getInstance();
        if (manager.hasCookies()) {
            headers.put("Cookie", manager.getCookie(url));
        }

        return headers;
    }

    private String getAuthorizationUrl(HttpWebResponse response) {
        Map<String, List<String>> headers = response.getResponseHeaders();

        if (headers.containsKey(LOCATION_HEADER_KEY)) {
            List<String> values = headers.get(LOCATION_HEADER_KEY);

            if (!values.isEmpty()) {
                return values.get(0);
            }
        }

        return null;
    }
}
