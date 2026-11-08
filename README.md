# flutter_appauth_web
AppAuth Web Plugin

How to use?
The same way you use the AppAuth
You only need to change the callback url to the -> http://xxxx:xxx/login-callback.html

How check if flutter are run on web?
```dart
import 'package:flutter/foundation.dart' show kIsWeb;
final String _callBackUrl = '${kIsWeb ? 'http://localhost:4000/login-callback.html' : 'com.example.myapp://login-callback'}';
 ```
login-callback.html
```html
<!DOCTYPE html>
<html>

<head>
    <script>
        const AUTH_DESTINATION_KEY = "auth_destination_url";
        const AUTH_RESPONSE_KEY = "auth_info";

        window.onload = function () {
            if (window.opener && window.opener !== window) { //Used when working as a popup. Uses post message to respond to the parent window
                window.opener.postMessage(location.href, "*");
            } else if (window.parent !== window) {
                window.parent.postMessage(location.href, "*");
            } else { //Used for full-page redirects.
                //Get the original page destination
                const destination = sessionStorage.getItem(AUTH_DESTINATION_KEY) || "/";
                sessionStorage.removeItem(AUTH_DESTINATION_KEY);
                //Store the current window location that will be used to get the information for authentication
                sessionStorage.setItem(AUTH_RESPONSE_KEY, window.location);

                //Redirect to where we're going so that we can restore state completely
                location.assign(destination);
            }
        }

    </script>
</head>

<body>

</body>

</html>
```

logout-callback.html
```html
<!DOCTYPE html>
<html>

<head>
    <script>
        const AUTH_RESPONSE_KEY = "auth_info";
        const CODE_VERIFIER_KEY = "auth_code_verifier";
        window.onload = function () {
            localStorage.removeItem(AUTH_RESPONSE_KEY);
            localStorage.removeItem(CODE_VERIFIER_KEY);
            const params = new URLSearchParams(window.location.search)
            if (params.has('redirect_uri')) {
                const redirect = params.get('redirect_uri');
                window.location.replace(redirect);
            } else {
                window.location.assign("/");
            }
        }
    </script>
</head>

<body>
</body>

</html>
```

### Authorization transaction

Each authorization request sends a cryptographically random `state` and a PKCE
challenge. The callback must return one matching `state` and one nonempty `code`
at the configured redirect origin and path. Errors, duplicate parameters,
fragments and replayed responses are rejected before token exchange.

The callback page must preserve `sessionStorage.auth_request_state` and
`sessionStorage.auth_code_verifier` when storing `auth_info` and returning to the
app. The plugin consumes those values once, on success or failure. Applications
should display a sign-in failure and offer an explicit retry instead of
immediately starting another authorization request.
