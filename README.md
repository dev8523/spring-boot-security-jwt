# spring-boot-security-jwt
An end-to-end application to learn about spring boot security with JWT.

# You will learn how to do JWT autherization in Spring Security.
- Create a new authentication API endpoint.
- Examine every incoming request for valid JWT & authorize.

# Step 1- A/authenticate API endpoint
- Accepts user ID and password
- Returns JWT as response

# Step 2- Intercept all incoming requests
- Extract JWT from the header
- Validate and set in execution context
For this, we have to create Filters
