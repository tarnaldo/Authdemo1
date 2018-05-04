package com.auth.demo.app.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * This WebSecurityConfigurerAdapter bean causes spring boot to drop the default implementation 
 * (new in spring boot 2).   oauth2Login enables redirect and handling of the automated callback.
 * The callback location is defined in properties.
 *  See OAuth2WebSecurityConfiguration for default OAuth security config.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
 
    @Override
    protected void configure(HttpSecurity http) throws Exception {
    	http
    		.authorizeRequests()
    		.antMatchers("/actuator/health").permitAll()
    		.antMatchers("/actuator/info").permitAll()
    		.antMatchers("/public/**").permitAll()
    		.anyRequest().authenticated()
    		.and()
    		.oauth2Login();
    }
    /*
     * Overriding and filter may be use to implement additional behavior 
     */
}