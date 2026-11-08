@TestOn('browser')
library;

import 'dart:async';
import 'dart:html' as web;
import 'package:flutter_appauth_web/authorization_exception.dart';

import 'package:flutter_appauth_platform_interface/flutter_appauth_platform_interface.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_appauth_web/flutter_appauth_web.dart';

const redirectUrl = 'https://mail.example.com/auth.html';
const state = 'expected-state';
const transactionKeys = [
  'auth_request_state',
  'auth_info',
  'auth_code_verifier',
  'auth_destination_url',
];
const configuration = AuthorizationServiceConfiguration(
  authorizationEndpoint: 'https://identity.example.com/authorize',
  tokenEndpoint: 'https://identity.example.com/token',
);

class SilentPlugin extends AppAuthWebPlugin {
  String? authorizationUrl;

  @override
  Future<String> openIframe(String url, String name) async {
    authorizationUrl = url;
    final generatedState = Uri.parse(url).queryParameters['state'];
    expect(
      web.window.sessionStorage['auth_request_state'],
      generatedState,
    );
    return '$redirectUrl?state=$generatedState&code=authorization-code';
  }
}

class TokenPlugin extends AppAuthWebPlugin {
  int exchanges = 0;

  @override
  Future<TokenResponse> requestToken(TokenRequest request) async {
    exchanges++;
    expect(request.authorizationCode, 'authorization-code');
    expect(request.codeVerifier, 'pkce-verifier');
    return TokenResponse('access', 'refresh', null, 'id', 'Bearer', null, null);
  }
}


class FailingPlugin extends AppAuthWebPlugin {
  @override
  Future<String> openIframe(String url, String name) async {
    throw StateError('iframe failed');
  }
}

class FailingConfigurationPlugin extends AppAuthWebPlugin {
  @override
  Future<AuthorizationServiceConfiguration> getConfiguration(
    AuthorizationServiceConfiguration? configuration, String? discovery, String? issuer) async {
    throw ArgumentError('configuration failed');
  }
}

class RedirectingPlugin extends AppAuthWebPlugin {
  @override
  Future<String> openIframe(String url, String name) async {
    throw AutoRedirectToAppAfterStoreAuthorizeDestinationUrlException();
  }
}

class PendingPlugin extends AppAuthWebPlugin {
  final callback = Completer<String>();
  final started = Completer<String>();

  @override
  Future<String> openIframe(String url, String name) {
    started.complete(url);
    return callback.future;
  }
}

void main() {
  AuthorizationRequest request({bool silent = false}) => AuthorizationRequest(
    'client',
    redirectUrl,
    serviceConfiguration: configuration,
    scopes: ['openid'],
    promptValues: silent ? ['none'] : null,
    additionalParameters: {'state': 'untrusted', 'hint': 'a&state=injected'},
  );

  void seed(String callback, {bool pending = true}) {
    if (pending) web.window.sessionStorage['auth_request_state'] = state;
    web.window.sessionStorage['auth_info'] = callback;
    web.window.sessionStorage['auth_code_verifier'] = 'pkce-verifier';
    web.window.sessionStorage['auth_destination_url'] = 'https://mail.example.com';
  }

  void expectClean() {
    for (final key in transactionKeys) {
      expect(web.window.sessionStorage[key], isNull, reason: key);
    }
  }

  setUp(() {
    for (final key in transactionKeys) {
      web.window.sessionStorage.remove(key);
    }
  });
  tearDown(() {
    for (final key in transactionKeys) {
      web.window.sessionStorage.remove(key);
    }
  });

  test(
    'generates unique 256-bit URL-safe state and preserves request parameters',
    () async {
      final plugin = SilentPlugin();
      final authRequest = request(silent: true);
      final originalParameters = authRequest.additionalParameters;
      final first = await plugin.authorize(authRequest);
      final firstState = Uri.parse(
        plugin.authorizationUrl!,
      ).queryParameters['state'];
      expect(firstState, matches(RegExp(r'^[A-Za-z0-9_-]{43}$')));
      expect(first.authorizationCode, 'authorization-code');
      expect(first.codeVerifier, hasLength(128));
      expect(Uri.parse(plugin.authorizationUrl!).queryParametersAll['state'], [
        firstState,
      ]);
      expect(
        Uri.parse(plugin.authorizationUrl!).queryParameters['hint'],
        'a&state=injected',
      );
      expect(authRequest.additionalParameters, same(originalParameters));
      expectClean();
      await plugin.authorize(authRequest);
      expect(
        Uri.parse(plugin.authorizationUrl!).queryParameters['state'],
        isNot(firstState),
      );
      expectClean();
    },
  );

  test(
    'accepts matching callback and consumes state and PKCE verifier once',
    () async {
      seed('$redirectUrl?state=$state&code=authorization-code');
      final result = await AppAuthWebPlugin().authorize(request());
      expect(result.authorizationCode, 'authorization-code');
      expect(result.codeVerifier, 'pkce-verifier');
      expectClean();
      seed('$redirectUrl?state=$state&code=authorization-code', pending: false);
      await expectLater(
        AppAuthWebPlugin().authorize(request()),
        throwsStateError,
      );
      expectClean();
    },
  );

  test(
    'inherited token exchange runs only after successful validation',
    () async {
      final plugin = TokenPlugin();
      final tokenRequest = AuthorizationTokenRequest(
        'client',
        redirectUrl,
        serviceConfiguration: configuration,
        scopes: ['openid'],
      );
      seed('$redirectUrl?state=wrong&code=authorization-code');
      await expectLater(
        plugin.authorizeAndExchangeCode(tokenRequest),
        throwsStateError,
      );
      expect(plugin.exchanges, 0);
      expectClean();
      seed('$redirectUrl?state=$state&code=authorization-code');
      final response = await plugin.authorizeAndExchangeCode(tokenRequest);
      expect(response.accessToken, 'access');
      expect(plugin.exchanges, 1);
      expectClean();
    },
  );

  for (final callback in [
    '',
    'not a URL',
    '$redirectUrl?code=code',
    '$redirectUrl?state=&code=code',
    '$redirectUrl?state=wrong&code=code',
    '$redirectUrl?state=$state&state=$state&code=code',
    '$redirectUrl?state=$state&code=one&code=two',
    '$redirectUrl?state=$state',
    '$redirectUrl?state=$state&code=',
    '$redirectUrl?state=$state&code=code&error=access_denied',
    '$redirectUrl?state=$state&code=code#fragment',
    '$redirectUrl?state=$state&code=code#',
    'https://evil.example.com/auth.html?state=$state&code=code',
    'http://mail.example.com/auth.html?state=$state&code=code',
    'https://mail.example.com:444/auth.html?state=$state&code=code',
    'https://mail.example.com/other.html?state=$state&code=code',
    'https://user@mail.example.com/auth.html?state=$state&code=code',
    '$redirectUrl?state=%XX&code=code',
  ]) {
    test(
      'rejects invalid callback and clears transaction: $callback',
      () async {
        seed(callback);
        await expectLater(
          AppAuthWebPlugin().authorize(request()),
          throwsStateError,
        );
        expectClean();
      },
    );
  }

  test(
    'clears transaction when upstream detects missing PKCE verifier',
    () async {
      seed('$redirectUrl?state=$state&code=code');
      web.window.sessionStorage.remove('auth_code_verifier');
      await expectLater(
        AppAuthWebPlugin().authorize(request()),
        throwsArgumentError,
      );
      expectClean();
    },
  );
  test('iframe failure clears state and verifier', () async {
    await expectLater(FailingPlugin().authorize(request(silent: true)), throwsStateError);
    expectClean();
  });

  test('intentional navigation retains the pending transaction', () async {
    await expectLater(RedirectingPlugin().authorize(request(silent: true)),
      throwsA(isA<AutoRedirectToAppAfterStoreAuthorizeDestinationUrlException>()));
    expect(web.window.sessionStorage['auth_request_state'], isNotEmpty);
    expect(web.window.sessionStorage['auth_code_verifier'], hasLength(128));
    expect(web.window.sessionStorage['auth_info'], isNull);
  });

  test('configuration failure removes stale transaction data', () async {
    web.window.sessionStorage['auth_request_state'] = 'old-state';
    web.window.sessionStorage['auth_code_verifier'] = 'old-verifier';
    await expectLater(FailingConfigurationPlugin().authorize(request()), throwsArgumentError);
    expectClean();
  });

  test('concurrent authorize does not destroy an active transaction', () async {
    final plugin = PendingPlugin();
    final first = plugin.authorize(request(silent: true));
    final uri = Uri.parse(await plugin.started.future);
    await expectLater(plugin.authorize(request(silent: true)), throwsStateError);
    final state = uri.queryParameters['state'];
    expect(web.window.sessionStorage['auth_request_state'], state);
    plugin.callback.complete('$redirectUrl?state=$state&code=authorization-code');
    expect((await first).authorizationCode, 'authorization-code');
    expectClean();
  });

  test('empty verifier is rejected before token exchange', () async {
    final plugin = TokenPlugin();
    seed('$redirectUrl?state=$state&code=authorization-code');
    web.window.sessionStorage['auth_code_verifier'] = '';
    await expectLater(plugin.authorizeAndExchangeCode(AuthorizationTokenRequest(
      'client', redirectUrl, serviceConfiguration: configuration, scopes: ['openid'])),
      throwsArgumentError);
    expect(plugin.exchanges, 0);
    expectClean();
  });

  test('origin-only redirect accepts the browser-normalized root path', () async {
    seed('https://mail.example.com/?state=$state&code=authorization-code');
    final result = await AppAuthWebPlugin().authorize(AuthorizationRequest(
      'client', 'https://mail.example.com',
      serviceConfiguration: configuration, scopes: ['openid']));
    expect(result.authorizationCode, 'authorization-code');
    expectClean();
  });

}
