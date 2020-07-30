package com.debasish.springsecurityjpa.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.debasish.springsecurityjpa.models.AuthenticationRequest;
import com.debasish.springsecurityjpa.models.AuthenticationResponse;
import com.debasish.springsecurityjpa.services.MyUserDetailsService;
import com.debasish.springsecurityjpa.services.utils.JwtUtil;

@RestController
public class HomeResourceController {

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private MyUserDetailsService myUserDetailsService;

	@Autowired
	private JwtUtil jwtUtil;

	@GetMapping("/hello")
	public String hello() {
		return "Hello World";
	}

	// This will generate a JWT token (tested in the postman)
	@PostMapping(value = "/authenticate")
	public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {
		try {
			// 1. IF authentication will happen here with the username and password if it's success then fine 
			// ELSE goes to catch block
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
					authenticationRequest.getUserName(), authenticationRequest.getPassword()));
		} catch (BadCredentialsException e) {
			// if doesn't authenticate then it will throw the exception
			throw new Exception("Incorrect username or password", e);
		}
		// 3. It will take load the user details as per user name.
		final UserDetails userDetails = myUserDetailsService.loadUserByUsername(authenticationRequest.getUserName());
		
		// 2. It will create a JWT token taking the user details
		final String jwt = jwtUtil.generateToken(userDetails);

		// 4. If it successfully authenticate, set the response in the payload response.
		return ResponseEntity.ok(new AuthenticationResponse(jwt));
	}

}
