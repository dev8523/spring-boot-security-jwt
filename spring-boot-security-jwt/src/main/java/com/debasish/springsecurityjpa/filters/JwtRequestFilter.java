package com.debasish.springsecurityjpa.filters;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.debasish.springsecurityjpa.services.MyUserDetailsService;
import com.debasish.springsecurityjpa.services.utils.JwtUtil;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

	@Autowired
	private MyUserDetailsService myUserDetailsService;

	@Autowired
	private JwtUtil jwtUtil;

	// It will examine the incoming request for the JWT in the header
	// it will check for the right header and see if that JWT is valid.
	// Work of this filter: If it finds the valid JWT,
	// it's gonna get the use details out of the UserDetailService and save it in
	// the security context.
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		final String authorizationHeader = request.getHeader("Authorization");

		String userName = null;
		String jwt = null;

		if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) { // it will check if the header
																						// has a value that starts with
																						// Bearer space.
			jwt = authorizationHeader.substring(7); // storing the jwt after Bearer and a space
			userName = jwtUtil.extractUsername(jwt); // will extract the username from the token
		}

		if (userName != null && SecurityContextHolder.getContext().getAuthentication() == null) {

			UserDetails userDetails = this.myUserDetailsService.loadUserByUsername(userName);

			if (jwtUtil.validateToken(jwt, userDetails)) {

				// Spring security uses UsernamePasswordAuthenticationToken for managing
				// authentication in the name of userName and password.
				UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
						userDetails, null, userDetails.getAuthorities());
				usernamePasswordAuthenticationToken
						.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
			}
		}
		filterChain.doFilter(request, response); // basically saying to continue the chain.
													// It's saying to other filters in the filter chains i have entered
													// the filter
													// chain and did my job now you can continue doing your job.
	}

}
