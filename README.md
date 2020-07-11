## Golang JWT Template

Notes Using JWT with Golang
Authenticates requests using access tokens and if expired, requests can be made using a refresh token. 
After a successful refresh token confirmation,new tokens are created and saved to Redis for future authentication.



Tokens are maintained in a Redis instance.