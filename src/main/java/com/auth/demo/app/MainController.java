package com.auth.demo.app;

import java.util.Collections;
import java.util.Map;

import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.client.RestTemplate;

/**
 * This controller handles initial name lookup from the default / location.  This
 * occurs after the initial redirect callback from the authorization server.
 * Additional endpoints return userinfo and demonstrate secured
 * update and read calls to an API base on position which is passed as scope
 * This will be altered to use role from the profile in the next version
 */
@Controller
public class MainController {

	private OAuth2AuthorizedClientService authorizedClientService;

	private static final Logger log = LoggerFactory.getLogger(MainController.class);

	@Autowired
	private RestTemplateBuilder restTemplateBuilder;

	@Autowired
	private Environment env;

	public MainController(OAuth2AuthorizedClientService authorizedClientService) {
		this.authorizedClientService = authorizedClientService;
	}

	@RequestMapping("/")
	public String index(Model model, OAuth2AuthenticationToken authentication) {

		OAuth2AuthorizedClient authorizedClient = this.getAuthorizedClient(authentication);
		if (authentication != null) {
			model.addAttribute("userName", authentication.getName());
			log.debug("userName:" + authentication.getName());
			if (authorizedClient != null) {
				model.addAttribute("clientName", authorizedClient.getClientRegistration().getClientName());
				log.debug("clientName:" + authorizedClient.getClientRegistration().getClientName());
				// updateRole(authentication);
			}
		}
		return "index";
	}

	@RequestMapping("/userinfo")
	public String userinfo(Model model, OAuth2AuthenticationToken authenticationToken) {
		log.debug("enter userinfo");
		OAuth2AuthorizedClient authorizedClient = this.getAuthorizedClient(authenticationToken);
		Map userAttributes = Collections.emptyMap();
		String userInfoEndpointUri = authorizedClient.getClientRegistration().getProviderDetails().getUserInfoEndpoint()
				.getUri();
		String appClientId = authorizedClient.getClientRegistration().getClientId();
		String appClientSecret = authorizedClient.getClientRegistration().getClientSecret();
		if (authorizedClient != null) {
			log.debug("Scopes: " + authorizedClient.getAccessToken().getScopes().toString());
			log.debug("token: " + authorizedClient.getAccessToken().getTokenValue());

			if (!StringUtils.isEmpty(userInfoEndpointUri)) {
				userInfoEndpointUri = userInfoEndpointUri + "?access_token="
						+ authorizedClient.getAccessToken().getTokenValue();
				log.debug("userInfoEndpointUri: " + userInfoEndpointUri);

				RestTemplate restTemplate = restTemplateBuilder.basicAuthorization(appClientId, appClientSecret)
						.build();
				userAttributes = restTemplate.getForObject(userInfoEndpointUri, Map.class);
				log.debug("userAttribute Map: " + userAttributes.toString());
			}
		} else {
			log.debug("Not Authorized");
		}
		userAttributes.put("scopes", authorizedClient.getAccessToken().getScopes().toString());
		model.addAttribute("userAttributes", userAttributes);

		return "userinfo";
	}

	@RequestMapping(value = "/updateData", method = RequestMethod.GET)
	public String updateData(Model model, OAuth2AuthenticationToken authentication) {
		// Mask value to show not authorized
		model.addAttribute("privateData1", "#######");
		model.addAttribute("privateData2", "#######");
		if (roleCheck(authentication, "manager")) {
			log.debug("manager role - update enabled ]");
			// Make API Call to
			String apiUpdateUri = env.getProperty("spring.security.oauth2.api.auth0.api-update-uri");
			log.debug("update API: " + apiUpdateUri);
			try {
				HttpHeaders headers = getApiHeader(authentication);
				JSONObject responseJson = new JSONObject();
				JSONObject request = new JSONObject();
				request.put("id", "key_identifier");
				request.put("privateData1", "Secret1");
				request.put("privateData2", "Secret2");
				headers.setContentType(MediaType.APPLICATION_JSON);
				log.debug("request.toString() " + request.toString());
				HttpEntity<String> entity = new HttpEntity<String>(request.toString(), headers);
				log.debug("entity: " + entity.toString());

				RestTemplate restTemplate = new RestTemplate();
				ResponseEntity<String> jwtTokenResponse = restTemplate.exchange(apiUpdateUri, HttpMethod.PUT, entity,
						String.class);
				if (jwtTokenResponse.getStatusCode() == HttpStatus.OK) {
					responseJson = new JSONObject(jwtTokenResponse.getBody());
					log.debug("API Update message " + responseJson.toString());
				} else if (jwtTokenResponse.getStatusCode() == HttpStatus.UNAUTHORIZED) {
					log.debug("HttpStatus.UNAUTHORIZED ");
				}

			} catch (Exception e) {
				log.debug("Error creating request: " + e.toString());
			}
			// Assume update occurred and just echo back the results
			model.addAttribute("privateData1", "Secret1");
			model.addAttribute("privateData2", "Secret2");
		} 
		return "updatedata";
	}

	@RequestMapping(value = "/readData", method = RequestMethod.GET)
	public String readData(Model model, OAuth2AuthenticationToken authentication) throws JSONException {
		model.addAttribute("publicData1", "#######");
		model.addAttribute("publicData2", "#######");
		if (roleCheck(authentication, "user") || roleCheck(authentication, "manager")) {
			// Make the call demo the Read
			String apiReadUri = env.getProperty("spring.security.oauth2.api.auth0.api-read-uri") + "?id=123";
			log.debug("update API: " + apiReadUri);
			HttpHeaders headers = getApiHeader(authentication);
			JSONObject responseJson = new JSONObject();

			HttpEntity<String> entity = new HttpEntity<String>(headers);
			log.debug("entity: " + entity.toString());

			RestTemplate restTemplate = new RestTemplate();
			ResponseEntity<String> jwtTokenResponse = restTemplate.exchange(apiReadUri, HttpMethod.GET, entity,
					String.class);
			if (jwtTokenResponse.getStatusCode() == HttpStatus.OK) {
				responseJson = new JSONObject(jwtTokenResponse.getBody());
				log.debug("API Update message " + responseJson.toString());
				log.debug(" returned " + responseJson.getString("publicData1"));
				model.addAttribute("publicData1", responseJson.getString("publicData1"));
				model.addAttribute("publicData2", responseJson.getString("publicData2"));
			} else if (jwtTokenResponse.getStatusCode() == HttpStatus.UNAUTHORIZED) {
				log.debug("HttpStatus.UNAUTHORIZED ");
			}

		}
		return "readdata";
	}

	/*
	 * Check the scope found in the Authorized Client
	 */
	private boolean roleCheck(OAuth2AuthenticationToken authentication, String scope) {
		OAuth2AuthorizedClient authorizedClient = this.getAuthorizedClient(authentication);
		log.debug("roleCheck");
		boolean hasScope = false;
		hasScope = authorizedClient.getAccessToken().getScopes().contains(scope);
		return hasScope;
	}

	/*
	 * Use the OAuth Token to get the OAuth2 Authorized Client
	 */
	private OAuth2AuthorizedClient getAuthorizedClient(OAuth2AuthenticationToken authenticationToken) {
		log.debug("Getting authorized client");
		if (authenticationToken != null) {
			log.debug("authentication auth client reg id: " + authenticationToken.getAuthorizedClientRegistrationId());
			log.debug("authentication auth name: " + authenticationToken.getName());
			OAuth2AuthorizedClient client = this.authorizedClientService.loadAuthorizedClient(
					authenticationToken.getAuthorizedClientRegistrationId(), authenticationToken.getName());
			log.debug("auth client loaded: " + client);
			return client;
		}
		return null;
	}

	private String getAPIAccessToken(OAuth2AuthenticationToken authenticationToken) throws JSONException {
		// This could be revised to cache and reuse a token until it expires
		log.debug("getAPIAccessToken");
		OAuth2AuthorizedClient authorizedClient = this.getAuthorizedClient(authenticationToken);
		if (authorizedClient != null) {
			String authTokenUri = authorizedClient.getClientRegistration().getProviderDetails().getTokenUri();
			String appClientId = authorizedClient.getClientRegistration().getClientId();
			String appClientSecret = authorizedClient.getClientRegistration().getClientSecret();
			String apiAudience = env.getProperty("spring.security.oauth2.api.auth0.audience");
			log.debug("apiAudience: " + apiAudience);
			JSONObject userJson = new JSONObject();
			JSONObject jsonRequest = new JSONObject();
			jsonRequest.put("grant_type", "client_credentials");
			jsonRequest.put("client_id", appClientId);
			jsonRequest.put("client_secret", appClientSecret);
			jsonRequest.put("audience", apiAudience);
			log.debug("jsonRequest: " + jsonRequest.toString());
			// set headers
			HttpHeaders headers = new HttpHeaders();
			headers.setContentType(MediaType.APPLICATION_JSON);
			HttpEntity<String> entity = new HttpEntity<String>(jsonRequest.toString(), headers);

			RestTemplate restTemplate = restTemplateBuilder.basicAuthorization(appClientId, appClientSecret).build();
			ResponseEntity<String> jwtTokenResponse = restTemplate.exchange(authTokenUri, HttpMethod.POST, entity,
					String.class);
			if (jwtTokenResponse.getStatusCode() == HttpStatus.OK) {
				userJson = new JSONObject(jwtTokenResponse.getBody());
				log.debug("API Bearer Token: " + userJson.getString("access_token"));
				return userJson.getString("access_token");
			} else if (jwtTokenResponse.getStatusCode() == HttpStatus.UNAUTHORIZED) {
				log.debug ("Invalid credentials to get Bearer Token");
			}
		}
		return "Nothing";
	}

	private HttpHeaders getApiHeader(OAuth2AuthenticationToken authenticationToken) throws JSONException {
		log.debug("<<<Enter getAPIHeaders>>>");
		String apiJwtToken = getAPIAccessToken(authenticationToken);
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_JSON);
		headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + apiJwtToken);
		log.debug("headers: " + headers.toString());
		log.debug("<<<Exit getAPIHeaders>>>");
		return headers;
	}
}
