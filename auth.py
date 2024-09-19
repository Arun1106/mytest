import jwt
import requests
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from cryptography.hazmat.primitives import serialization
from jwt.algorithms import RSAAlgorithm

EXPECTED_ISSUER = "https://oauth.us.auth0.com/"
JWKS_URL = EXPECTED_ISSUER + ".well-known/jwks.json"
def generate_policy(principal_id, effect, resource):
    """Generates an IAM policy."""
    auth_response = {
        "principalId": principal_id
    }

    if effect and resource:
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": effect,
                    "Resource": resource
                }
            ]
        }
        auth_response["policyDocument"] = policy_document

    return auth_response


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
        print(f"Audience: {audience}")
        public_key = get_public_key(token)
        
        # Decode and verify the token
        decoded_token = jwt.decode(token, public_key, algorithms=["RS256"], audience=audience, issuer=EXPECTED_ISSUER)
        return decoded_token
    except ExpiredSignatureError:
        return "Token has expired"
    except InvalidTokenError as e:
        return f"Token is invalid: {str(e)}"

def lambda_handler(event, context):
    # Replace this with your actual token
    token = event["authorizationToken"]
    method_arn=event["methodArn"]
    result = verify_token(token)
    
    if isinstance(result, str):
        print(result)
        return generate_policy("user", "Deny", method_arn)
    else:
        print("Token is valid.")
        print("Decoded Token:", result)
        principal_id = result["sub"]
        return generate_policy(principal_id, "Allow", method_arn)
