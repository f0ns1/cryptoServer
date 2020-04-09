package com.crypto.server.cryptoserver.config;


import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.springframework.ws.config.annotation.EnableWs;

@Configuration
@EnableWebMvc
@EnableWs
@EnableAutoConfiguration
public class ConfigurationClass extends WebMvcConfigurerAdapter {

	@Override
	public void addResourceHandlers(ResourceHandlerRegistry registry) {
		registry.addResourceHandler("/img/**", "/css/**", "/js/**").addResourceLocations(
				 "classpath:/static/img/", "classpath:/static/css/",
				"classpath:/static/js/");
	}

}
