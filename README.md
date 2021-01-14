# spring-boot-security-jwt
An end-to-end application to learn about spring boot security with JWT.

# Why JWT
- One of the best secure way to communicate from client to server. 
- To follow Stateless authentication mechanism -> means our input is not stored in server memory/Cookies.

# You will learn how to do JWT autherization in Spring Security.
- Create a new authentication API endpoint.
- Examine every incoming request for valid JWT & authorize.

# Step 1- Authenticate API endpoint
- Accepts user ID and password
- Returns JWT as response

# Step 2- Intercept all incoming requests
- Extract JWT from the header
- Validate and set in execution context

Note: For Step 2, we have to create our own Filters extending the OncePerRequestFilter.
