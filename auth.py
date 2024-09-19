import json
import jwt
import requests
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

EXPECTED_ISSUER = "https://.us.auth0.com/"
JWKS_URL = EXPECTED_ISSUER + ".well-known/jwks.json"

def get_audience_from_token(token):
    try:
        # Decode the token without verifying the signature to get the 'aud' claim
        unverified_payload = jwt.decode(token, options={"verify_signature": False})
        return unverified_payload.get("aud")
    except Exception as e:
        raise Exception(f"Error decoding token: {str(e)}")

def get_public_key(token):
    try:
        # Fetch JWKS (public keys)
        jwks = requests.get(JWKS_URL).json()

        # Get the kid (Key ID) from the token header
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header["kid"]

        # Find the public key that matches the kid
        rsa_key = None
        for key in jwks["keys"]:
            if key["kid"] == kid:
                rsa_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
                break
        
        if not rsa_key:
            raise Exception("Public key not found.")

        return rsa_key
    except Exception as e:
        raise Exception(f"Error fetching or parsing public key: {str(e)}")

def verify_token(token):
    try:
        # Get the public key for verification
        audience = get_audience_from_token(token)
        public_key = get_public_key(token)
        
        # Decode and verify the token
        decoded_token = jwt.decode(token, public_key, algorithms=["RS256"], audience=audience, issuer=EXPECTED_ISSUER)
        return decoded_token
    except ExpiredSignatureError:
        return "Token has expired"
    except InvalidTokenError as e:
        return f"Token is invalid: {str(e)}"
    except Exception as e:
        return f"Error verifying token: {str(e)}"

#def lambda_handler(event, context):
def lambda_handler():
    #token=event['authorizationToken']
    token="S"
        # Verify the token
    result = verify_token(token)
    print(result)
    
    if isinstance(result, dict):
        return generatePolicy(result.get('sub', ''), 'Allow',"asasa")
    else:
        raise Exception('Unauthorized')

def generatePolicy(principalId, effect, resource):
    policyDocument = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "execute-api:Invoke",
                "Effect": effect,
                "Resource": resource
            }
        ]
    }
    return {
        "principalId": principalId,
        "policyDocument": policyDocument,
        "context": {
            "stringKey": "stringval",
            "numberKey": 123,
            "booleanKey": True
        }
    }

lambda_handler()
