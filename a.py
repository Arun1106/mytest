import jwt
import requests
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from jwt.algorithms import RSAAlgorithm


EXPECTED_ISSUER = "https://dev-v51fd04jmlvzsg2r.us.auth0.com/"
JWKS_URL = EXPECTED_ISSUER + ".well-known/jwks.json"
def get_audience_from_token(token):
    unverified_payload = jwt.decode(token, options={"verify_signature": False})
    return unverified_payload.get("aud")

def get_public_key(token):
    # Fetch JWKS (public keys)
    jwks = requests.get(JWKS_URL).json()

    # Get the kid (Key ID) from the token header
    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header["kid"]
    
    # Find the public key that matches the kid
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == kid:
            rsa_key = RSAAlgorithm.from_jwk(key)
            break
    
    if not rsa_key:
        raise InvalidTokenError("Public key not found.")
    
    return rsa_key

def verify_token(token):
    try:
        # Get the public key for verification
        audience = get_audience_from_token(token)
        print(audience)
        public_key = get_public_key(token)
        
        
        # Decode and verify the token
        decoded_token = jwt.decode(token, public_key, algorithms=["RS256"], audience=audience, issuer=EXPECTED_ISSUER)
        return decoded_token
    except ExpiredSignatureError:
        return "Token has expired"
    except InvalidTokenError as e:
        return f"Token is invalid: {str(e)}"

def main():
    # Replace this with your actual token
    token=""    
    
    result = verify_token(token)
    
    if isinstance(result, str):
        print(result)
    else:
        print("Token is valid.")
        print("Decoded Token:", result)

if __name__ == "__main__":
    main() 
