library flutter_appauth_web;

import 'dart:async';
import 'dart:convert';

import 'dart:math';
import 'dart:typed_data';
import 'dart:html' as html;
import 'dart:core';
import 'package:flutter_appauth_web/authorization_exception.dart';
import 'package:flutter_web_plugins/flutter_web_plugins.dart';
import 'package:http/http.dart' as http;

import 'package:flutter_appauth_platform_interface/flutter_appauth_platform_interface.dart';
import 'package:pointycastle/digests/sha256.dart';

/// A Calculator.
class AppAuthWebPlugin extends FlutterAppAuthPlatform {
  static const String _charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  static const String _DISCOVERY_ERROR_MESSAGE_FORMAT = "Error retrieving discovery document: [error: discovery_failed, description: %2]";
  static const String _TOKEN_ERROR_MESSAGE_FORMAT = "Failed to get token: [error: token_failed, description: %2]";

  static const String _CODE_VERIFIER_STORAGE = "auth_code_verifier";
  static const String _AUTHORIZE_DESTINATION_URL = "auth_destination_url";
  static const String _AUTH_RESPONSE_INFO = "auth_info";
  static const String _STATE_STORAGE = "auth_request_state";

  Uri? _redirectUri;
  bool _isAuthorizing = false;

  static registerWith(Registrar registrar) {
    FlutterAppAuthPlatform.instance = AppAuthWebPlugin();
  }

  @override
  Future<AuthorizationTokenResponse> authorizeAndExchangeCode(AuthorizationTokenRequest request,) async {
    final authResult = await authorize(
      AuthorizationRequest(
        request.clientId,
        request.redirectUrl,
        loginHint: request.loginHint,
        scopes: request.scopes,
        serviceConfiguration: request.serviceConfiguration,
        additionalParameters: request.additionalParameters,
        allowInsecureConnections: request.allowInsecureConnections!,
        discoveryUrl: request.discoveryUrl,
        issuer: request.issuer,
        externalUserAgent: request.externalUserAgent ??
            ExternalUserAgent.asWebAuthenticationSession,
        promptValues: request.promptValues,
      ),
    );

    final tokenResponse = await requestToken(TokenRequest(request.clientId, request.redirectUrl,
        clientSecret: request.clientSecret,
        serviceConfiguration: request.serviceConfiguration,
        allowInsecureConnections: request.allowInsecureConnections!,
        authorizationCode: authResult.authorizationCode,
        codeVerifier: authResult.codeVerifier,
        discoveryUrl: request.discoveryUrl,
        grantType: "authorization_code",
        issuer: request.issuer));

    return AuthorizationTokenResponse(tokenResponse.accessToken, tokenResponse.refreshToken, tokenResponse.accessTokenExpirationDateTime, tokenResponse.idToken,
        tokenResponse.tokenType, tokenResponse.scopes, authResult.authorizationAdditionalParameters, tokenResponse.tokenAdditionalParameters);
  }

  @override
  Future<AuthorizationResponse> authorize(AuthorizationRequest request) async {
    if (_isAuthorizing) throw StateError('Authorization is already in progress');
    _isAuthorizing = true;
    var redirecting = false;
    try {
      _redirectUri = Uri.parse(request.redirectUrl);
      final authUrl = html.window.sessionStorage[_AUTH_RESPONSE_INFO];
      // An empty response is still a callback attempt, not a new sign-in.
      if (authUrl != null) {
        final verifier = html.window.sessionStorage[_CODE_VERIFIER_STORAGE] ?? '';
        return processLoginResult(authUrl, verifier);
      }

      final configuration = await getConfiguration(
        request.serviceConfiguration, request.discoveryUrl, request.issuer);
      request.serviceConfiguration = configuration;
      final random = Random.secure();
      final verifier = List.generate(128,
        (_) => _charset[random.nextInt(_charset.length)]).join();
      final challenge = base64Url.encode(SHA256Digest().process(
        Uint8List.fromList(verifier.codeUnits))).replaceAll('=', '');
      final state = base64Url.encode(List.generate(32,
        (_) => random.nextInt(256))).replaceAll('=', '');
      html.window.sessionStorage[_STATE_STORAGE] = state;
      html.window.sessionStorage[_CODE_VERIFIER_STORAGE] = verifier;

      // Uri encodes both keys and values; additional parameters cannot inject
      // a second state or override the generated authorization/PKCE parameters.
      final endpoint = Uri.parse(configuration.authorizationEndpoint);
      final authUri = endpoint.replace(queryParameters: <String, dynamic>{
        ...endpoint.queryParametersAll,
        ...?request.additionalParameters,
        'client_id': request.clientId,
        'redirect_uri': request.redirectUrl,
        'response_type': 'code',
        'scope': request.scopes?.join(' ') ?? '',
        'code_challenge_method': 'S256',
        'code_challenge': challenge,
        'state': state,
        if (request.loginHint != null) 'login_hint': request.loginHint!,
        if (request.promptValues != null) 'prompt': request.promptValues!,
      }).toString();

      if (request.promptValues?.contains('none') == true) {
        return processLoginResult(await openIframe(authUri, 'auth'), verifier);
      }
      html.window.sessionStorage[_AUTHORIZE_DESTINATION_URL] = html.window.location.href;
      html.window.location.assign(authUri);
      throw AutoRedirectToAppAfterStoreAuthorizeDestinationUrlException();
    } on AutoRedirectToAppAfterStoreAuthorizeDestinationUrlException {
      // The new document resumes this transaction using sessionStorage.
      redirecting = true;
      rethrow;
    } finally {
      if (!redirecting) _clearTransaction();
      _redirectUri = null;
      _isAuthorizing = false;
    }
  }

  @override
  Future<TokenResponse> token(TokenRequest request) {
    return requestToken(request);
  }

  @override
  Future<EndSessionResponse> endSession(EndSessionRequest request) async {
    final AuthorizationServiceConfiguration serviceConfiguration = await getConfiguration(request.serviceConfiguration, request.discoveryUrl, request.issuer);
    String uri = "${serviceConfiguration.endSessionEndpoint}?id_token_hint=${request.idTokenHint}";

    if (request.idTokenHint != null && request.postLogoutRedirectUrl != null) {
      uri += "&post_logout_redirect_uri=${Uri.encodeQueryComponent(request.postLogoutRedirectUrl!)}";
    }

    if (request.postLogoutRedirectUrl != null && request.state != null) {
      uri += "&state=${request.state}";
    }

    // lets redirect to the endsession uri
    html.window.location.assign(uri);

    return EndSessionResponse(null);
  }

  Future<TokenResponse> requestToken(TokenRequest request) async {
    final serviceConfiguration = await getConfiguration(request.serviceConfiguration, request.discoveryUrl, request.issuer);

    request.serviceConfiguration = serviceConfiguration; //Fill in the values from the discovery doc if needed for future calls

    var body = {"client_id": request.clientId, "grant_type": request.grantType, "redirect_uri": request.redirectUrl};

    if (request.clientSecret != null) body["client_secret"] = request.clientSecret;

    if (request.authorizationCode != null) body["code"] = request.authorizationCode;
    if (request.codeVerifier != null) body["code_verifier"] = request.codeVerifier;
    if (request.refreshToken != null) body["refresh_token"] = request.refreshToken;
    if (request.scopes != null && request.scopes!.isNotEmpty) body["scopes"] = request.scopes!.join(" ");

    if (request.additionalParameters != null) body.addAll(request.additionalParameters!);

    final response = await http.post(Uri.parse(serviceConfiguration.tokenEndpoint), body: body);

    final Map<String, dynamic> jsonResponse = jsonDecode(response.body);

    if (response.statusCode != 200) {
      print(jsonResponse["error"].toString());
      throw ArgumentError(_TOKEN_ERROR_MESSAGE_FORMAT.replaceAll("%2", jsonResponse["error"]?.toString() ?? response.reasonPhrase ?? "Unknown Error"));
    }
    List<String>? scopes =
        jsonResponse["scope"] is String == true ? ((jsonResponse["scope"].split(' ') as List?)?.cast<String>()) : (jsonResponse["scope"] as List?)?.cast<String>();
    return TokenResponse(
      jsonResponse["access_token"].toString(),
      jsonResponse["refresh_token"] == null ? null : jsonResponse["refresh_token"].toString(),
      DateTime.now().add(new Duration(seconds: jsonResponse["expires_in"])),
      jsonResponse["id_token"].toString(),
      jsonResponse["token_type"].toString(),
      scopes,
      jsonResponse,
    );
  }

  AuthorizationResponse processLoginResult(String loginResult, String codeVerifier) {
    try {
      final result = Uri.tryParse(loginResult);
      final redirect = _redirectUri;
      if (result == null || redirect == null || !result.hasAuthority ||
          result.scheme != redirect.scheme || result.host != redirect.host ||
          result.port != redirect.port || result.userInfo.isNotEmpty ||
          _callbackPath(result) != _callbackPath(redirect) || result.hasFragment) {
        throw StateError('Invalid OAuth callback URL');
      }
      final parameters = result.queryParametersAll;
      final state = html.window.sessionStorage[_STATE_STORAGE];
      final states = parameters['state'];
      final codes = parameters['code'];
      if (state == null || state.isEmpty || states == null ||
          states.length != 1 || states.single != state ||
          codes == null || codes.length != 1 || codes.single.isEmpty ||
          parameters.containsKey('error')) {
        throw StateError('Invalid OAuth authorization response');
      }
      if (codeVerifier.isEmpty ||
          codeVerifier != html.window.sessionStorage[_CODE_VERIFIER_STORAGE]) {
        throw ArgumentError('No matching code verifier found');
      }
      return AuthorizationResponse(
        authorizationCode: codes.single,
        codeVerifier: codeVerifier,
        authorizationAdditionalParameters: result.queryParameters,
      );
    } finally {
      // Consume the transaction synchronously, including rejected callbacks,
      // before any token exchange can begin.
      _clearTransaction();
    }
  }

  String _callbackPath(Uri uri) =>
      uri.path.isEmpty && (uri.scheme == 'https' || uri.scheme == 'http')
          ? '/' : uri.path;

  void _clearTransaction() {
    for (final key in [_STATE_STORAGE, _AUTH_RESPONSE_INFO,
      _CODE_VERIFIER_STORAGE, _AUTHORIZE_DESTINATION_URL]) {
      html.window.sessionStorage.remove(key);
    }
  }

  //to-do Cache this based on the url
  Future<AuthorizationServiceConfiguration> getConfiguration(AuthorizationServiceConfiguration? serviceConfiguration, String? discoveryUrl, String? issuer) async {
    if ((discoveryUrl == null || discoveryUrl == '') && (issuer == null || issuer == '') && serviceConfiguration == null)
      throw ArgumentError('You must specify either a discoveryUrl, issuer, or serviceConfiguration');

    if (serviceConfiguration != null) return serviceConfiguration;

    //Handle lookup here.
    if (discoveryUrl == null || discoveryUrl == '') discoveryUrl = "$issuer/.well-known/openid-configuration";

    final response = await http.get(Uri.parse(discoveryUrl));
    if (response.statusCode != 200) throw UnsupportedError(_DISCOVERY_ERROR_MESSAGE_FORMAT.replaceAll("%2", response.reasonPhrase ?? "Unknown Error"));

    final jsonResponse = jsonDecode(response.body);
    return AuthorizationServiceConfiguration(
      authorizationEndpoint: jsonResponse["authorization_endpoint"].toString(),
      tokenEndpoint: jsonResponse["token_endpoint"].toString(),
      endSessionEndpoint: jsonResponse["end_session_endpoint"].toString(),
    );
  }

  Future<String> openPopUp(String url, String name, int width, int height, bool center, {String? additionalOptions}) async {
    var options = 'width=$width,height=$height,toolbar=no,location=no,directories=no,status=no,menubar=no,copyhistory=no';
    if (center) {
      final top = (html.window.outerHeight - height) / 2 + (html.window.screen?.available.top ?? 0);
      final left = (html.window.outerWidth - width) / 2 + (html.window.screen?.available.left ?? 0);

      options += 'top=$top,left=$left';
    }

    if (additionalOptions != null && additionalOptions != '') options += ',$additionalOptions';

    final child = html.window.open(url, name, options);
    final c = new Completer<String>();

    html.window.onMessage.first.then((event) {
      final url = event.data.toString();
      c.complete(url);
      child.close();
    });

    //This handles the user closing the window without a response
    while (!c.isCompleted) {
      await Future.delayed(Duration(milliseconds: 500));
      if ((child.closed ?? false) && !c.isCompleted) c.completeError(StateError('User Closed'));

      if (c.isCompleted) break;
    }

    return c.future;
  }

  Future<String> openIframe(String url, String name) async {
    final child = html.IFrameElement();
    child.name = name;
    child.src = url;
    child.height = '10';
    child.width = '10';
    child.style.border = 'none';
    child.style.display = 'none';

    html.querySelector("body")?.children.add(child);

    final c = new Completer<String>();

    html.window.onMessage.first.then((event) {
      final url = event.data.toString();
      c.complete(url);
      html.querySelector("body")?.children.remove(child);
    });

    return c.future;
  }
}
