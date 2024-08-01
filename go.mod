module github.com/VMadhuranga/chirpy

go 1.22.5

replace github.com/VMadhuranga/chirpy/database v0.0.0 => ./database

require github.com/VMadhuranga/chirpy/database v0.0.0

require golang.org/x/crypto v0.25.0

require github.com/joho/godotenv v1.5.1

require github.com/golang-jwt/jwt/v5 v5.2.1
