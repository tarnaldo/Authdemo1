package com.auth.demo.app;

import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.env.Environment;

@SpringBootApplication
public class Application {
	private static final Logger log = LoggerFactory.getLogger(Application.class);

	public static void main(String[] args) throws Exception {
		Environment env = SpringApplication.run(Application.class, args).getEnvironment();
		log.info("Running with Spring profiles(s): {}", Arrays.toString(env.getActiveProfiles()));
	}
}
