package com.crypto.server.cryptoserver.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Controller
public class ApplicationController {

	@RequestMapping("/")
	public String index(HttpServletRequest request, HttpServletResponse response) {
		System.out.println("crypto application server !!");
		return "index";
	}

	@RequestMapping("/encrypt")
	public String encryptController(HttpServletRequest request, HttpServletResponse response) {
		System.out.println("crypto application server !!");
		return "encrypt";
	}

	@RequestMapping("/decrypt")
	public String decryptController(HttpServletRequest request, HttpServletResponse response) {
		System.out.println("crypto application server !!");
		return "decrypt";
	}

	@RequestMapping("/sign")
	public String signController(HttpServletRequest request, HttpServletResponse response) {
		System.out.println("crypto application server !!");
		return "sign";
	}

	@RequestMapping("/certificates")
	public String certificatesController(HttpServletRequest request, HttpServletResponse response) {
		System.out.println("crypto application server !!");
		return "certificates";
	}

	@RequestMapping("/contact")
	public String contactController(HttpServletRequest request, HttpServletResponse response) {
		System.out.println("crypto application server !!");
		return "contact";
	}
}
