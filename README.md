# Authdemo1 - OIDC Sign-on and Authorization Demonstration 

This demonstration consists of two applications 
* Authdemo1 
* [Authdemo2](https://github.com/tarnaldo/Authdemo2)

## Summary 
Authdemo1 is as Spring Boot 2 Java application configured to use Auth0 for authentication use Open ID Connect 1.0.  After authenticating, it using Spring security. In future enhancements, Spring security will be configured to rely on the JWT token.  Reuse will use a cookie until expiration.

In addition to sign-on, this web app will display logged in user details, simulate data updating(and viewing) based on the users position/authority.  

This version depends on the entitlement being passed in the scope.  An addition version will use this passed through the role as an additional claim.  Spring can expose the ID Token with some additional code added to the security configuration. 

New to Spring Boot 2 is a nice feature that will accept a virtual endpoint for a login callback. Using the authorization code grant flow redirects back to this endpoint. Spring Boot Security will then intercept it, exchange the auth code for an ID Token and register the user into Spring Security.  

The application demonstrates this simplified flow and reduced code needed.  It may be extended as needed.  The approach reduces the application code.  TymeLeaf is integrate into as a means to demonstrate this.  This approach is viable with other UIs.  It may be worth considering using this approach to lead into other frameworks.   

## Configuration Details
The configuration properties rely on a service to service use of client IDs and Secrets:
* The first client id is the current Authdemo1 app.  It is trusted in the Auth0 configuration to create an access token for the API app Authdemo2.
* The second client id is the Authdemo2 app.  The authorization will add it as the audience in the JWT token


### User Configuration
* Users are configured on Auth0 
* User position information is passed in the scope and as role in he additional claims

## Reference Links
* [Auth0](http://autho.com)
* [Spring Security](https://docs.spring.io/spring-security/site/docs/current/reference/html/jc.html)
* [Spring Boot Login](https://github.com/spring-projects/spring-security/tree/master/samples/boot/oauth2login)
  This contains examples this demonstration is based on. This has details on setting up the application.yml
  
## Special Notes When Reusing
**Be Sure to remove log statements containing secrets.**
The log statements are there for demonstration purposes and should be revised
